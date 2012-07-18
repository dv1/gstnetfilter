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



#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "gstnetfilter.h"



/**** Debugging ****/

GST_DEBUG_CATEGORY_STATIC(netfilter_debug);
#define GST_CAT_DEFAULT netfilter_debug



/**** Constants ****/


enum
{
	DUMMY_PORT = 0x0100
};


enum
{
	PROP_0 = 0, /* GStreamer disallows properties with id 0 -> using dummy enum to prevent 0 */
	PROP_FILTER_ADDRESS,
	PROP_ENABLED
};



/**** Function declarations ****/

/* This function is invoked when the sink pad receives data */
static GstFlowReturn gst_netfilter_chain(GstPad *pad, GstBuffer *packet);

/* Property accessors */
static void gst_netfilter_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec);
static void gst_netfilter_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);



/**** GStreamer boilerplate ****/

GST_BOILERPLATE(GstNetfilter, gst_netfilter, GstElement, GST_TYPE_ELEMENT)



/**** Pads ****/

static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE(
	"sink",
	GST_PAD_SINK,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS("ANY")
);

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE(
	"src",
	GST_PAD_SRC,
	GST_PAD_ALWAYS,
	GST_STATIC_CAPS("ANY")
);



/**** Function definition ****/

static void gst_netfilter_base_init(gpointer klass)
{
	GstElementClass *element_class = GST_ELEMENT_CLASS(klass);

	gst_element_class_set_details_simple(
		element_class,
		"Network packet filter",
		"Network/Filter",
		"Filters buffers if they are netbuffers, based on their source IP address",
		"Carlos Rafael Giani <dv@pseudoterminal.org>"
	);

	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&sink_template));
	gst_element_class_add_pad_template(element_class, gst_static_pad_template_get(&src_template));
}


static void gst_netfilter_class_init(GstNetfilterClass *klass)
{
	GObjectClass *object_class;
	GstElementClass *element_class;

	GST_DEBUG_CATEGORY_INIT(netfilter_debug, "netfilter", 0, "Network packet filter");

	object_class = G_OBJECT_CLASS(klass);
	element_class = GST_ELEMENT_CLASS(klass);

	/* Set functions */
	object_class->set_property = GST_DEBUG_FUNCPTR(gst_netfilter_set_property);
	object_class->get_property = GST_DEBUG_FUNCPTR(gst_netfilter_get_property);

	/* Install properties */
	g_object_class_install_property(
		object_class,
		PROP_FILTER_ADDRESS,
		g_param_spec_string(
			"filter-address",
			"IP address to filter",
			"Address to be used for filtering; only packets with this source address are pushed downstream",
			"",
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
	g_object_class_install_property(
		object_class,
		PROP_ENABLED,
		g_param_spec_boolean(
			"enabled",
			"Enable/disable filtering",
			"If set to true, filtering is enabled, otherwise it is disabled, and just passes through packets",
			TRUE,
			G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS
		)
	);
}


static void gst_netfilter_init(GstNetfilter *netfilter, GstNetfilterClass *klass)
{
	GstElement *element;

	klass = klass;
	
	element = GST_ELEMENT(netfilter);

	/* Create pads out of the templates defined earlier */
	netfilter->sinkpad = gst_pad_new_from_static_template(&sink_template, "sink");
	netfilter->srcpad = gst_pad_new_from_static_template(&src_template, "src");

	netfilter->filtering_enabled = TRUE;

	/* Set chain and setcaps functions for the sink pad */
	gst_pad_set_chain_function(netfilter->sinkpad, gst_netfilter_chain);

	/* Add the pads to the element */
	gst_element_add_pad(element, netfilter->sinkpad);
	gst_element_add_pad(element, netfilter->srcpad);
}


static GstFlowReturn gst_netfilter_chain(GstPad *pad, GstBuffer *packet)
{
	GstNetfilter *netfilter;
	GstFlowReturn ret;

	netfilter = GST_NETFILTER(GST_PAD_PARENT(pad));
	ret = GST_FLOW_OK;

	if (netfilter->filtering_enabled && GST_IS_NETBUFFER(packet))
	{
		/* Packet is a netbuffer -> get its source address and compare */

		GstNetAddress const *orig_packet_source_address = &(GST_NETBUFFER(packet)->from);
		GstNetAddress modified_source_address;

		/*
		Since we are only interested in comparing the address, and not the port,
		we have to copy the original source address, and create a new one with the port number
		set to DUMMY_PORT (it is not possible to let gst_netaddress_equal() compare only the addresses)
		*/
		{
			guint8 addr[16];
			guint16 port;
			GstNetType type;

			type = gst_netaddress_get_net_type(orig_packet_source_address);
			gst_netaddress_get_address_bytes(orig_packet_source_address, addr, &port);
			gst_netaddress_set_address_bytes(&modified_source_address, type, addr, DUMMY_PORT);
		}

		/* Debug output; doing this check to avoid unnecessary to_string calls */
		if (gst_debug_category_get_threshold(GST_CAT_DEFAULT) >= GST_LEVEL_DEBUG)
		{
			char str1[GST_NETADDRESS_MAX_LEN + 1];
			char str2[GST_NETADDRESS_MAX_LEN + 1];
			str1[GST_NETADDRESS_MAX_LEN] = 0;
			str2[GST_NETADDRESS_MAX_LEN] = 0;
			gst_netaddress_to_string(&modified_source_address, str1, GST_NETADDRESS_MAX_LEN);
			gst_netaddress_to_string(&(netfilter->filter_address), str2, GST_NETADDRESS_MAX_LEN);
			GST_DEBUG_OBJECT(netfilter, "Received buffer is a network packet with source address %s (filter address is %s; port numbers are ignored)", str1, str2);
		}

		if (gst_netaddress_equal(&(netfilter->filter_address), &modified_source_address))
		{
			/* Addresses match; pass through the packet */
			GST_DEBUG_OBJECT(netfilter, "Received packet's source address is a match -> passing through");
			ret = gst_pad_push(netfilter->srcpad, packet);
		}
		else
		{
			/* Addresses do not match; drop the packet */
			GST_DEBUG_OBJECT(netfilter, "Received packet's source address does not match the filter address -> dropping");
			gst_buffer_unref(packet);
		}
	}
	else
	{
		/* Packet is not a netbuffer, or filtering is disabled; just pass it through */
		ret = gst_pad_push(netfilter->srcpad, packet);
	}

	return ret;
}


static void gst_netfilter_set_property(GObject *object, guint prop_id, GValue const *value, GParamSpec *pspec)
{
	GstNetfilter *netfilter;
	GST_OBJECT_LOCK(object);
	netfilter = GST_NETFILTER(object);

	switch (prop_id)
	{
		case PROP_FILTER_ADDRESS:
		{
			/*
			The address can be specified in many ways, as hostname, as IPv4 address, as IPv6 address..
			getaddrinfo is used to get an IP address out of what has been specified
			*/

			int error;
			struct addrinfo *result;
			char const *address_str;

			address_str = g_value_get_string(value);
			error = getaddrinfo(address_str, NULL, NULL, &result);

			if (error != 0)
			{
				GST_ERROR_OBJECT(netfilter, "Could not set filter address property: %s", gai_strerror(error));
			}
			else
			{
				switch (result->ai_family)
				{
					case AF_INET:
					{
						struct sockaddr_in const *sockaddr_ipv4 = (struct sockaddr_in const *)(result->ai_addr);
						struct in_addr const *addr = &(sockaddr_ipv4->sin_addr);
						gst_netaddress_set_ip4_address(&(netfilter->filter_address), addr->s_addr, DUMMY_PORT);
						break;
					}
					case AF_INET6:
					{
						struct sockaddr_in6 const *sockaddr_ipv6 = (struct sockaddr_in6 const *)(result->ai_addr);
						struct in6_addr const *addr = &(sockaddr_ipv6->sin6_addr);
						gst_netaddress_set_ip6_address(&(netfilter->filter_address), (guint8 *)(addr->s6_addr), DUMMY_PORT);
						break;
					}
					default:
						GST_ERROR_OBJECT(netfilter, "Could not set filter address property: unknown address family %d", result->ai_family);
				}
			}

			freeaddrinfo(result);

			break;
		}
		case PROP_ENABLED:
		{
			netfilter->filtering_enabled = g_value_get_boolean(value);
			GST_DEBUG_OBJECT(netfilter, "Filtering is %s", netfilter->filtering_enabled ? "enabled" : "disabled");
			break;
		}
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}

	GST_OBJECT_UNLOCK(object);
}


static void gst_netfilter_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	GstNetfilter *netfilter;
	GST_OBJECT_LOCK(object);
	netfilter = GST_NETFILTER(object);

	switch (prop_id)
	{
		case PROP_FILTER_ADDRESS:
		{
			char str[GST_NETADDRESS_MAX_LEN + 1];
			str[GST_NETADDRESS_MAX_LEN] = 0;

			/* Returning the address as IP address */
			gst_netaddress_to_string(&(netfilter->filter_address), str, GST_NETADDRESS_MAX_LEN);
			g_value_set_string(value, str);
			break;
		}
		case PROP_ENABLED:
		{
			g_value_set_boolean(value, netfilter->filtering_enabled);
			break;
		}
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}

	GST_OBJECT_UNLOCK(object);
}





#define PACKAGE "package"


static gboolean plugin_init(GstPlugin *plugin)
{
	if (!gst_element_register(plugin, "netfilter", GST_RANK_NONE, gst_netfilter_get_type())) return FALSE;
	return TRUE;
}

GST_PLUGIN_DEFINE(
	GST_VERSION_MAJOR,
	GST_VERSION_MINOR,
	"netfilter",
	"Network packet filter",
	plugin_init,
	"1.0",
	"LGPL",
	"netfilter",
	"http://no-url-yet"
)
