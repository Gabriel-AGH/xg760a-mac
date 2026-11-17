/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Gabriel-AGH */
/*
 * User-space USB access on macOS through IOKit (IOUSBLib).
 */
#include "usbdev.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"

#define MAX_EP 16
#define MAX_READERS 4
#define MAX_READER_BUFS 16

struct pipe_info {
	uint8_t present;
	uint8_t ref;
	uint8_t type;
	uint16_t max_packet;
};

struct reader;

struct reader_buf {
	struct reader *rd;
	uint8_t *buf;
	int pending;
};

struct reader {
	struct usbdev *d;
	uint8_t pipe_ref;
	size_t bufsize;
	int nbufs;
	int errors;
	usbdev_read_cb cb;
	void *ctx;
	struct reader_buf bufs[MAX_READER_BUFS];
};

struct usbdev {
	IOUSBDeviceInterface650 **dev;
	IOUSBInterfaceInterface650 **intf;
	uint16_t vid, pid, bcd;
	uint8_t speed;
	uint64_t entry_id;
	struct pipe_info in[MAX_EP], out[MAX_EP];

	pthread_t loop_thread;
	int loop_started;
	CFRunLoopRef loop;
	CFRunLoopSourceRef source;

	pthread_mutex_t lock;
	pthread_cond_t cond;
	int gone;
	int stopping;
	int pending_reads;

	struct reader readers[MAX_READERS];
	int n_readers;
};

static int kr_to_errno(IOReturn kr)
{
	switch (kr) {
	case kIOReturnSuccess:
		return 0;
	case kIOUSBTransactionTimeout:
	case kIOReturnTimeout:
		return -ETIMEDOUT;
	case kIOReturnNoDevice:
	case kIOReturnNotResponding:
	case kIOReturnNotAttached:
		return -ENODEV;
	case kIOUSBPipeStalled:
		return -EPIPE;
	case kIOReturnExclusiveAccess:
		return -EBUSY;
	case kIOReturnNotPermitted:
	case kIOReturnNotPrivileged:
		return -EACCES;
	case kIOReturnAborted:
		return -ECANCELED;
	default:
		return -EIO;
	}
}

static io_service_t find_device(const uint16_t (*ids)[2], size_t count)
{
	for (size_t i = 0; i < count; i++) {
		CFMutableDictionaryRef m = IOServiceMatching("IOUSBHostDevice");
		SInt32 vid = ids[i][0], pid = ids[i][1];
		CFNumberRef nv, np;
		io_iterator_t it = IO_OBJECT_NULL;
		io_service_t svc;

		if (!m)
			return IO_OBJECT_NULL;
		nv = CFNumberCreate(NULL, kCFNumberSInt32Type, &vid);
		np = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
		CFDictionarySetValue(m, CFSTR("idVendor"), nv);
		CFDictionarySetValue(m, CFSTR("idProduct"), np);
		CFRelease(nv);
		CFRelease(np);
		/* consumes one reference to m */
		/* MACH_PORT_NULL selects the default port on every macOS
		 * version (kIOMainPortDefault only exists since macOS 12) */
		if (IOServiceGetMatchingServices(MACH_PORT_NULL, m, &it) !=
		    KERN_SUCCESS)
			continue;
		svc = IOIteratorNext(it);
		IOObjectRelease(it);
		if (svc)
			return svc;
	}
	return IO_OBJECT_NULL;
}

int usbdev_open(struct usbdev **out, const uint16_t (*ids)[2], size_t count)
{
	io_service_t svc;
	IOCFPlugInInterface **plug = NULL;
	SInt32 score = 0;
	IOReturn kr;
	struct usbdev *d;

	*out = NULL;
	svc = find_device(ids, count);
	if (!svc)
		return -ENODEV;

	d = calloc(1, sizeof(*d));
	if (!d) {
		IOObjectRelease(svc);
		return -ENOMEM;
	}
	IORegistryEntryGetRegistryEntryID(svc, &d->entry_id);
	pthread_mutex_init(&d->lock, NULL);
	pthread_cond_init(&d->cond, NULL);

	kr = IOCreatePlugInInterfaceForService(svc, kIOUSBDeviceUserClientTypeID,
					       kIOCFPlugInInterfaceID, &plug,
					       &score);
	IOObjectRelease(svc);
	if (kr != kIOReturnSuccess || !plug) {
		xg_log(XG_LOG_ERR, "USB: cannot create device plug-in (0x%08x)\n",
		       kr);
		free(d);
		return kr_to_errno(kr) ? kr_to_errno(kr) : -EIO;
	}
	(*plug)->QueryInterface(plug,
				CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID650),
				(LPVOID *)&d->dev);
	(*plug)->Release(plug);
	if (!d->dev) {
		free(d);
		return -EIO;
	}

	kr = (*d->dev)->USBDeviceOpen(d->dev);
	if (kr == kIOReturnExclusiveAccess)
		kr = (*d->dev)->USBDeviceOpenSeize(d->dev);
	if (kr != kIOReturnSuccess) {
		xg_log(XG_LOG_ERR, "USB: cannot open the device (0x%08x)%s\n", kr,
		       kr == kIOReturnExclusiveAccess ?
			       ": another program is using it" : "");
		(*d->dev)->Release(d->dev);
		free(d);
		return kr_to_errno(kr);
	}

	(*d->dev)->GetDeviceVendor(d->dev, &d->vid);
	(*d->dev)->GetDeviceProduct(d->dev, &d->pid);
	(*d->dev)->GetDeviceReleaseNumber(d->dev, &d->bcd);
	(*d->dev)->GetDeviceSpeed(d->dev, &d->speed);
	*out = d;
	return 0;
}

uint16_t usbdev_vid(const struct usbdev *d) { return d->vid; }
uint16_t usbdev_pid(const struct usbdev *d) { return d->pid; }
uint16_t usbdev_bcd(const struct usbdev *d) { return d->bcd; }

int usbdev_is_high_speed(const struct usbdev *d)
{
	return d->speed >= kUSBDeviceSpeedHigh;
}

int usbdev_is_gone(const struct usbdev *d)
{
	return d->gone;
}

int usbdev_control(struct usbdev *d, uint8_t request_type, uint8_t request,
		   uint16_t value, uint16_t index, void *data, uint16_t len,
		   unsigned int timeout_ms)
{
	IOUSBDevRequestTO req;
	IOReturn kr;

	memset(&req, 0, sizeof(req));
	req.bmRequestType = request_type;
	req.bRequest = request;
	req.wValue = value;
	req.wIndex = index;
	req.wLength = len;
	req.pData = data;
	req.noDataTimeout = timeout_ms;
	req.completionTimeout = timeout_ms;
	kr = (*d->dev)->DeviceRequestTO(d->dev, &req);
	if (kr != kIOReturnSuccess) {
		xg_log(XG_LOG_DBG,
		       "USB: control request 0x%02x failed (0x%08x)\n", request,
		       kr);
		return kr_to_errno(kr);
	}
	return (int)req.wLenDone;
}

static void *loop_main(void *arg)
{
	struct usbdev *d = arg;

	pthread_setname_np("xg760a-usb");
	pthread_mutex_lock(&d->lock);
	d->loop = CFRunLoopGetCurrent();
	CFRetain(d->loop);
	CFRunLoopAddSource(d->loop, d->source, kCFRunLoopDefaultMode);
	pthread_cond_broadcast(&d->cond);
	pthread_mutex_unlock(&d->lock);
	CFRunLoopRun();
	return NULL;
}

static void interface_teardown(struct usbdev *d)
{
	if (!d->intf)
		return;
	usbdev_stop_readers(d);
	if (d->loop_started) {
		CFRunLoopStop(d->loop);
		pthread_join(d->loop_thread, NULL);
		CFRelease(d->loop);
		d->loop = NULL;
		d->loop_started = 0;
	}
	if (d->source) {
		CFRelease(d->source);
		d->source = NULL;
	}
	(*d->intf)->USBInterfaceClose(d->intf);
	(*d->intf)->Release(d->intf);
	d->intf = NULL;
	memset(d->in, 0, sizeof(d->in));
	memset(d->out, 0, sizeof(d->out));
	for (int i = 0; i < d->n_readers; i++)
		for (int j = 0; j < d->readers[i].nbufs; j++)
			free(d->readers[i].bufs[j].buf);
	memset(d->readers, 0, sizeof(d->readers));
	d->n_readers = 0;
	d->stopping = 0;
}

int usbdev_configure(struct usbdev *d)
{
	IOUSBConfigurationDescriptorPtr desc = NULL;
	IOUSBFindInterfaceRequest req;
	IOCFPlugInInterface **plug = NULL;
	io_iterator_t it = IO_OBJECT_NULL;
	io_service_t svc = IO_OBJECT_NULL;
	SInt32 score = 0;
	UInt8 n = 0;
	IOReturn kr;

	interface_teardown(d);

	kr = (*d->dev)->GetConfigurationDescriptorPtr(d->dev, 0, &desc);
	if (kr != kIOReturnSuccess || !desc) {
		xg_log(XG_LOG_ERR, "USB: no configuration descriptor (0x%08x)\n",
		       kr);
		return kr_to_errno(kr) ? kr_to_errno(kr) : -EIO;
	}
	kr = (*d->dev)->SetConfiguration(d->dev, desc->bConfigurationValue);
	if (kr != kIOReturnSuccess) {
		xg_log(XG_LOG_ERR, "USB: SetConfiguration failed (0x%08x)\n", kr);
		return kr_to_errno(kr);
	}

	/* the interface service is published asynchronously */
	for (int tries = 0; tries < 40 && !svc; tries++) {
		req.bInterfaceClass = kIOUSBFindInterfaceDontCare;
		req.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
		req.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
		req.bAlternateSetting = kIOUSBFindInterfaceDontCare;
		kr = (*d->dev)->CreateInterfaceIterator(d->dev, &req, &it);
		if (kr == kIOReturnSuccess) {
			svc = IOIteratorNext(it);
			IOObjectRelease(it);
		}
		if (!svc)
			usleep(50 * 1000);
	}
	if (!svc) {
		xg_log(XG_LOG_ERR, "USB: interface 0 not found\n");
		return -ENODEV;
	}

	kr = IOCreatePlugInInterfaceForService(svc,
					       kIOUSBInterfaceUserClientTypeID,
					       kIOCFPlugInInterfaceID, &plug,
					       &score);
	IOObjectRelease(svc);
	if (kr != kIOReturnSuccess || !plug) {
		xg_log(XG_LOG_ERR,
		       "USB: cannot create interface plug-in (0x%08x)\n", kr);
		return kr_to_errno(kr) ? kr_to_errno(kr) : -EIO;
	}
	(*plug)->QueryInterface(plug,
				CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID650),
				(LPVOID *)&d->intf);
	(*plug)->Release(plug);
	if (!d->intf)
		return -EIO;

	kr = (*d->intf)->USBInterfaceOpen(d->intf);
	if (kr == kIOReturnExclusiveAccess)
		kr = (*d->intf)->USBInterfaceOpenSeize(d->intf);
	if (kr != kIOReturnSuccess) {
		xg_log(XG_LOG_ERR, "USB: cannot open interface 0 (0x%08x)\n", kr);
		(*d->intf)->Release(d->intf);
		d->intf = NULL;
		return kr_to_errno(kr);
	}

	(*d->intf)->GetNumEndpoints(d->intf, &n);
	for (UInt8 ref = 1; ref <= n; ref++) {
		UInt8 dir, num, type, interval;
		UInt16 mps;
		struct pipe_info *p;

		if ((*d->intf)->GetPipeProperties(d->intf, ref, &dir, &num, &type,
						  &mps, &interval) !=
		    kIOReturnSuccess)
			continue;
		if (num >= MAX_EP)
			continue;
		p = (dir == kUSBIn) ? &d->in[num] : &d->out[num];
		p->present = 1;
		p->ref = ref;
		p->type = type;
		p->max_packet = mps;
		xg_log(XG_LOG_DBG, "USB: endpoint %u %s type %u max packet %u\n",
		       num, dir == kUSBIn ? "IN " : "OUT", type, mps);
	}

	kr = (*d->intf)->CreateInterfaceAsyncEventSource(d->intf, &d->source);
	if (kr != kIOReturnSuccess || !d->source) {
		xg_log(XG_LOG_ERR, "USB: no async event source (0x%08x)\n", kr);
		return -EIO;
	}
	/* the interface keeps its own reference; hold one for the thread */
	CFRetain(d->source);

	pthread_mutex_lock(&d->lock);
	if (pthread_create(&d->loop_thread, NULL, loop_main, d) != 0) {
		pthread_mutex_unlock(&d->lock);
		return -EAGAIN;
	}
	d->loop_started = 1;
	while (!d->loop)
		pthread_cond_wait(&d->cond, &d->lock);
	pthread_mutex_unlock(&d->lock);
	return 0;
}

int usbdev_reenumerate(struct usbdev *d)
{
	IOReturn kr;

	interface_teardown(d);
	kr = (*d->dev)->USBDeviceReEnumerate(d->dev, 0);
	d->gone = 1;
	return kr_to_errno(kr);
}

int usbdev_reset_and_reopen(struct usbdev **dp, const uint16_t (*ids)[2],
			    size_t count)
{
	struct usbdev *d = *dp;
	uint64_t old_id = d->entry_id;
	int r;

	r = usbdev_reenumerate(d);
	usbdev_close(d);
	*dp = NULL;
	if (r)
		return r;

	/*
	 * The port reset makes the device disappear and come back as a new
	 * registry entry. Wait for that new entry rather than re-opening the
	 * dying one.
	 */
	for (int i = 0; i < 100; i++) {
		usleep(50 * 1000);
		if (usbdev_open(&d, ids, count) != 0)
			continue;
		if (d->entry_id != old_id || i >= 60) {
			*dp = d;
			return 0;
		}
		usbdev_close(d);
	}
	return -ENODEV;
}

int usbdev_ep_type(const struct usbdev *d, int ep, int dir_in)
{
	const struct pipe_info *p;

	if (ep < 0 || ep >= MAX_EP)
		return -1;
	p = dir_in ? &d->in[ep] : &d->out[ep];
	return p->present ? p->type : -1;
}

int usbdev_ep_max_packet(const struct usbdev *d, int ep, int dir_in)
{
	const struct pipe_info *p;

	if (ep < 0 || ep >= MAX_EP)
		return -1;
	p = dir_in ? &d->in[ep] : &d->out[ep];
	return p->present ? p->max_packet : -1;
}

/* --- blocking writes ---------------------------------------------------- */

struct sync_xfer {
	dispatch_semaphore_t sem;
	IOReturn result;
	uint32_t done;
	uint8_t data[];
};

static void sync_cb(void *refcon, IOReturn result, void *arg0)
{
	struct sync_xfer *x = refcon;

	x->result = result;
	x->done = (uint32_t)(uintptr_t)arg0;
	dispatch_semaphore_signal(x->sem);
}

int usbdev_write(struct usbdev *d, int ep, const void *data, size_t len,
		 unsigned int timeout_ms)
{
	const struct pipe_info *p;
	struct sync_xfer *x;
	IOReturn kr;
	int r;

	if (!d->intf || ep < 0 || ep >= MAX_EP || !d->out[ep].present)
		return -EINVAL;
	if (d->gone)
		return -ENODEV;
	p = &d->out[ep];

	if (p->type == USBDEV_XFER_BULK) {
		/* bulk pipes have native timeouts */
		kr = (*d->intf)->WritePipeTO(d->intf, p->ref, (void *)data,
					     (UInt32)len, timeout_ms, timeout_ms);
		if (kr == kIOUSBPipeStalled || kr == kIOUSBTransactionTimeout)
			(*d->intf)->ClearPipeStallBothEnds(d->intf, p->ref);
		return kr_to_errno(kr);
	}

	/*
	 * Interrupt pipes have no timeout variant: go through the async call
	 * and wait for its completion ourselves.
	 */
	x = malloc(sizeof(*x) + len);
	if (!x)
		return -ENOMEM;
	x->sem = dispatch_semaphore_create(0);
	x->result = kIOReturnError;
	x->done = 0;
	memcpy(x->data, data, len);

	kr = (*d->intf)->WritePipeAsync(d->intf, p->ref, x->data, (UInt32)len,
					sync_cb, x);
	if (kr != kIOReturnSuccess) {
		dispatch_release(x->sem);
		free(x);
		return kr_to_errno(kr);
	}
	if (dispatch_semaphore_wait(x->sem,
				    dispatch_time(DISPATCH_TIME_NOW,
						  (int64_t)timeout_ms *
							  NSEC_PER_MSEC)) != 0) {
		(*d->intf)->AbortPipe(d->intf, p->ref);
		if (dispatch_semaphore_wait(
			    x->sem, dispatch_time(DISPATCH_TIME_NOW,
						  2 * NSEC_PER_SEC)) != 0) {
			/* no completion at all: leak x rather than risk a
			 * late callback writing into freed memory */
			return -ETIMEDOUT;
		}
		(*d->intf)->ClearPipeStallBothEnds(d->intf, p->ref);
		dispatch_release(x->sem);
		free(x);
		return -ETIMEDOUT;
	}
	r = kr_to_errno(x->result);
	if (r == 0 && x->done != len)
		r = -EIO;
	if (x->result == kIOUSBPipeStalled)
		(*d->intf)->ClearPipeStallBothEnds(d->intf, p->ref);
	dispatch_release(x->sem);
	free(x);
	return r;
}

/* --- permanent readers -------------------------------------------------- */

static void reader_submit(struct reader_buf *rb);

static void reader_gone(struct reader *rd)
{
	struct usbdev *d = rd->d;
	int first;

	pthread_mutex_lock(&d->lock);
	first = !d->gone;
	d->gone = 1;
	pthread_mutex_unlock(&d->lock);
	if (first)
		rd->cb(rd->ctx, NULL, 0, USBDEV_ERR_GONE);
}

static void reader_cb(void *refcon, IOReturn result, void *arg0)
{
	struct reader_buf *rb = refcon;
	struct reader *rd = rb->rd;
	struct usbdev *d = rd->d;
	uint32_t len = (uint32_t)(uintptr_t)arg0;
	int stopping;

	pthread_mutex_lock(&d->lock);
	rb->pending = 0;
	d->pending_reads--;
	stopping = d->stopping;
	pthread_cond_broadcast(&d->cond);
	pthread_mutex_unlock(&d->lock);

	if (stopping)
		return;

	switch (result) {
	case kIOReturnSuccess:
		rd->errors = 0;
		rd->cb(rd->ctx, rb->buf, len, USBDEV_OK);
		break;
	case kIOReturnAborted:
	case kIOReturnNoDevice:
	case kIOReturnNotResponding:
	case kIOReturnNotAttached:
	case kIOReturnNotOpen:
		reader_gone(rd);
		return;
	case kIOReturnOverrun:
		/* more data than the buffer could hold: drop it */
		break;
	default:
		if (result == kIOUSBPipeStalled)
			(*d->intf)->ClearPipeStallBothEnds(d->intf, rd->pipe_ref);
		if (++rd->errors > 20) {
			xg_log(XG_LOG_ERR,
			       "USB: too many read errors (last 0x%08x)\n", result);
			reader_gone(rd);
			return;
		}
		xg_log(XG_LOG_DBG, "USB: read error 0x%08x\n", result);
		usleep(2000);
		break;
	}
	if (!d->gone)
		reader_submit(rb);
}

static void reader_submit(struct reader_buf *rb)
{
	struct reader *rd = rb->rd;
	struct usbdev *d = rd->d;
	IOReturn kr;

	pthread_mutex_lock(&d->lock);
	if (d->stopping) {
		pthread_mutex_unlock(&d->lock);
		return;
	}
	rb->pending = 1;
	d->pending_reads++;
	pthread_mutex_unlock(&d->lock);

	kr = (*d->intf)->ReadPipeAsync(d->intf, rd->pipe_ref, rb->buf,
				       (UInt32)rd->bufsize, reader_cb, rb);
	if (kr != kIOReturnSuccess) {
		pthread_mutex_lock(&d->lock);
		rb->pending = 0;
		d->pending_reads--;
		pthread_cond_broadcast(&d->cond);
		pthread_mutex_unlock(&d->lock);
		xg_log(XG_LOG_DBG, "USB: cannot queue a read (0x%08x)\n", kr);
		reader_gone(rd);
	}
}

int usbdev_start_reader(struct usbdev *d, int ep, size_t bufsize, int nbufs,
			usbdev_read_cb cb, void *ctx)
{
	struct reader *rd;

	if (!d->intf || ep < 0 || ep >= MAX_EP || !d->in[ep].present)
		return -EINVAL;
	if (d->n_readers >= MAX_READERS || nbufs < 1 || nbufs > MAX_READER_BUFS)
		return -EINVAL;

	rd = &d->readers[d->n_readers];
	memset(rd, 0, sizeof(*rd));
	rd->d = d;
	rd->pipe_ref = d->in[ep].ref;
	rd->bufsize = bufsize;
	rd->nbufs = nbufs;
	rd->cb = cb;
	rd->ctx = ctx;
	for (int i = 0; i < nbufs; i++) {
		rd->bufs[i].rd = rd;
		rd->bufs[i].buf = malloc(bufsize);
		if (!rd->bufs[i].buf)
			return -ENOMEM;
	}
	d->n_readers++;
	for (int i = 0; i < nbufs; i++)
		reader_submit(&rd->bufs[i]);
	return d->gone ? -ENODEV : 0;
}

void usbdev_stop_readers(struct usbdev *d)
{
	struct timespec deadline;

	if (!d->intf)
		return;
	pthread_mutex_lock(&d->lock);
	d->stopping = 1;
	pthread_mutex_unlock(&d->lock);

	for (int i = 0; i < d->n_readers; i++)
		(*d->intf)->AbortPipe(d->intf, d->readers[i].pipe_ref);

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 2;
	pthread_mutex_lock(&d->lock);
	while (d->pending_reads > 0) {
		if (pthread_cond_timedwait(&d->cond, &d->lock, &deadline) != 0)
			break;
	}
	pthread_mutex_unlock(&d->lock);
}

void usbdev_close(struct usbdev *d)
{
	if (!d)
		return;
	interface_teardown(d);
	if (d->dev) {
		(*d->dev)->USBDeviceClose(d->dev);
		(*d->dev)->Release(d->dev);
	}
	pthread_mutex_destroy(&d->lock);
	pthread_cond_destroy(&d->cond);
	free(d);
}
