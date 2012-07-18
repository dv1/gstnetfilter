/*
 *  Network packet filter for GStreamer
 *
 *  Copyright (C) 2012 Carlos Rafael Giani <dv@pseudoterminal.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */



#ifndef GSTNETFILTER_H
#define GSTNETFILTER_H

#include <gst/netbuffer/gstnetbuffer.h>
#include <gst/gst.h>


G_BEGIN_DECLS


typedef struct _GstNetfilter GstNetfilter;
typedef struct _GstNetfilterClass GstNetfilterClass;

/* standard type-casting and type-checking boilerplate... */
#define GST_TYPE_NETFILTER             (gst_netfilter_get_type())
#define GST_NETFILTER(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_NETFILTER, GstNetfilter))
#define GST_NETFILTER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), GST_TYPE_NETFILTER, GstNetfilterClass))
#define GST_IS_NETFILTER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), GST_TYPE_NETFILTER))
#define GST_IS_NETFILTER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), GST_TYPE_NETFILTER))

struct _GstNetfilter
{
	GstElement element;

	gboolean filtering_enabled;
	GstNetAddress filter_address;
	GstPad
		*sinkpad,
		*srcpad;
};

struct _GstNetfilterClass
{
	GstElementClass parent_class;
};

GType gst_netfilter_get_type(void);


G_END_DECLS


#endif

