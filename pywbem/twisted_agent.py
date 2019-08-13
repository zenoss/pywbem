##############################################################################
#
# Copyright (C) Zenoss, Inc. 2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

from base64 import b64encode
from twisted.internet import reactor, defer

from pywbem import CIMClass, CIMClassName, CIMInstance, CIMInstanceName, CIMError, CIMDateTime, cim_types, cim_xml, cim_obj
from pywbem.cim_constants import CIM_ERR_INVALID_PARAMETER
from .tupleparse import TupleParser

try:
    from elementtree.ElementTree import fromstring, tostring
except ImportError, arg:
    from xml.etree.ElementTree import fromstring, tostring

import six
import string, base64

from types import StringTypes
from datetime import datetime, timedelta

from twisted.web.http_headers import Headers
from twisted.web.client import FileBodyProducer
from twisted.web.client import Agent, readBody
from StringIO import StringIO
from twisted.internet.ssl import ClientContextFactory


class WBEMClientContextFactory(ClientContextFactory):
    """
    Need this to avoid error: getContext() takes exactly 1 argument (3 given)
    """
    def getContext(self, hostname, port):
        # FIXME: no attempt to verify certificates!
        return ClientContextFactory.getContext(self)

class BaseWBEMMethod(object):
    """Create instances of the WBEMClient class."""

    request_xml = None
    response_xml = None
    xml_header = '<?xml version="1.0" encoding="utf-8" ?>'

    def __init__(self, creds, operation, method, object, payload):
        self.creds = creds
        self.operation = operation
        self.method = method
        self.object = object
        self.payload = payload

    def imethodcallPayload(self, methodname, localnsp, **kwargs):
        """Generate the XML payload for an intrinsic methodcall."""

        param_list = [cim_xml.IPARAMVALUE(x[0], pywbem.tocimxml(x[1]))
                      for x in kwargs.items()]

        payload = cim_xml.CIM(
            cim_xml.MESSAGE(
                cim_xml.SIMPLEREQ(
                    cim_xml.IMETHODCALL(
                        methodname,
                        cim_xml.LOCALNAMESPACEPATH(
                            [cim_xml.NAMESPACE(ns)
                             for ns in string.split(localnsp, '/')]),
                        param_list)),
                '1001', '1.0'),
            '2.0', '2.0')

        return self.xml_header + payload.toxml()

    def methodcallPayload(self, methodname, obj, namespace, **kwargs):
        """Generate the XML payload for an extrinsic methodcall."""

        if isinstance(obj, CIMInstanceName):

            path = obj.copy()

            path.host = None
            path.namespace = None

            localpath = cim_xml.LOCALINSTANCEPATH(
                cim_xml.LOCALNAMESPACEPATH(
                    [cim_xml.NAMESPACE(ns)
                     for ns in string.split(namespace, '/')]),
                path.tocimxml())
        else:
            localpath = cim_xml.LOCALCLASSPATH(
                cim_xml.LOCALNAMESPACEPATH(
                    [cim_xml.NAMESPACE(ns)
                     for ns in string.split(namespace, '/')]),
                obj)

        def paramtype(obj):
            """Return a string to be used as the CIMTYPE for a parameter."""
            if isinstance(obj, cim_types.CIMType):
                return obj.cimtype
            elif type(obj) == bool:
                return 'boolean'
            elif isinstance(obj, StringTypes):
                return 'string'
            elif isinstance(obj, (datetime, timedelta)):
                return 'datetime'
            elif isinstance(obj, (CIMClassName, CIMInstanceName)):
                return 'reference'
            elif isinstance(obj, (CIMClass, CIMInstance)):
                return 'string'
            elif isinstance(obj, list):
                return paramtype(obj[0])
            raise TypeError('Unsupported parameter type "%s"' % type(obj))

        def paramvalue(obj):
            """Return a cim_xml node to be used as the value for a
            parameter."""
            if isinstance(obj, (datetime, timedelta)):
                obj = CIMDateTime(obj)
            if isinstance(obj, (cim_types.CIMType, bool, StringTypes)):
                return cim_xml.VALUE(cim_types.atomic_to_cim_xml(obj))
            if isinstance(obj, (CIMClassName, CIMInstanceName)):
                return cim_xml.VALUE_REFERENCE(obj.tocimxml())
            if isinstance(obj, (CIMClass, CIMInstance)):
                return cim_xml.VALUE(obj.tocimxml().toxml())
            if isinstance(obj, list):
                if isinstance(obj[0], (CIMClassName, CIMInstanceName)):
                    return cim_xml.VALUE_REFARRAY([paramvalue(x) for x in obj])
                return cim_xml.VALUE_ARRAY([paramvalue(x) for x in obj])
            raise TypeError('Unsupported parameter type "%s"' % type(obj))

        param_list = [cim_xml.PARAMVALUE(x[0],
                                         paramvalue(x[1]),
                                         paramtype(x[1]))
                      for x in kwargs.items()]

        payload = cim_xml.CIM(
            cim_xml.MESSAGE(
                cim_xml.SIMPLEREQ(
                    cim_xml.METHODCALL(methodname,
                                       localpath,
                                       param_list)),
                '1001', '1.0'),
            '2.0', '2.0')

        return self.xml_header + payload.toxml()

    def parseErrorAndResponse(self, data):
        """Parse returned XML for errors, then convert into
        appropriate Python objects."""

        xml = fromstring(data)
        error = xml.find('.//ERROR')

        if error is None:
            return xml

        try:
            code = int(error.attrib['CODE'])
        except ValueError:
            code = 0

        raise CIMError(code, error.attrib['DESCRIPTION'])

    def get_headers(self, creds, cim_method, namespace):
        """
        generates headers
        :param creds:
        :param classname:
        :param namespace:
        :param cim_method:
        :return:
        """
        headers_dict = {'CIMOperation': ['MethodCall'],
                        'CIMMethod': [cim_method],
                        'Content-type': ['application/xml; charset="utf-8"'],
                        'CIMObject': [namespace]}

        headers = Headers(headers_dict)
        auth_string = b64encode('%s:%s' % (creds[0], creds[1]))
        headers.addRawHeader('Authorization', 'Basic %s' % auth_string)
        return headers

    # common  BASE class
    def parseResponse(self, xml):
        """Parse returned XML and convert into appropriate Python
        objects.  Override in subclass"""

        pass

    def build_url(self, ssl, host, port):
        """
        Builds
        :param ssl:
        :param host:
        :param port:
        :return:
        """
        protocol = "https" if ssl else "http"
        return "%s://%s:%s" % (protocol, host, port)

    def cbResponse(self, res):
        d = readBody(res)
        return d

    def error(self, err):
        return err

# TODO: Eww - we should get rid of the tupletree, tupleparse modules
# and replace with elementtree based code.

import pywbem.tupletree

class ExecQuery(BaseWBEMMethod):
    def __init__(self, creds, QueryLanguage, Query, host, port, ssl, namespace = 'root/cimv2'):
        self.QueryLanguage = QueryLanguage
        self.Query = Query
        self.namespace = namespace
        self.cim_method = "ExecQuery"

        payload = self.imethodcallPayload(
            'ExecQuery',
            namespace,
            QueryLanguage = QueryLanguage,
            Query = Query)

        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))

        url = self.build_url(ssl, host, port)
        if ssl:
            # TODO  build SSL factory
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s:%s) at 0x%x>' % \
               (self.__class__, self.namespace, self.Query, id(self))

    def parseResponse(self, xml):
        tt = [pywbem.tupletree.xml_to_tupletree_sax(tostring(x), 'INSTANCE')
              for x in xml.findall('.//INSTANCE')]

        # returns CIMInstance
        tp = pywbem.tupleparse.TupleParser()
        return [tp.parse_instance(x) for x in tt]


class OpenEnumerateInstances(BaseWBEMMethod):
    """Factory to produce EnumerateInstances WBEM clients."""

    def __init__(self, creds, classname, host, port, ssl, namespace='root/cimv2', **kwargs):
        self.classname = classname
        self.namespace = namespace
        self.cim_method = "OpenEnumerateInstances"
        self.context = None
        self.property_filter = (None, None)
        self.result_component_key = None

        #if not kwargs.get('MaxObjectCount'):
        #    kwargs['MaxObjectCount'] = DEFAULT_ITER_MAXOBJECTCOUNT

        if 'PropertyFilter' in kwargs:
            self.property_filter = kwargs['PropertyFilter']
            del kwargs['PropertyFilter']

        if 'ResultComponentKey' in kwargs:
            self.result_component_key = kwargs['ResultComponentKey']
            del kwargs['ResultComponentKey']

        payload = self.imethodcallPayload(
            self.cim_method,
            namespace,
            ClassName=CIMClassName(classname),
            **kwargs)
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))
        url = self.build_url(ssl, host, port)
        if ssl:
            # TODO  build SSL factory
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s:%s) at 0x%x>' % \
               (self.__class__, self.namespace, self.classname, id(self))

    def parseResponse(self, xml):
        res = []
        part_results = {}
        results_for_monitoring = {}

        for paramvalue in xml.findall('.//PARAMVALUE'):
            str_paramvalue = tostring(paramvalue)
            tuple_paramvalue = pywbem.tupletree.xml_to_tupletree_sax(str_paramvalue, 'PARAMVALUE')
            # returns 3-part tuple; name, type, value
            tuple = TupleParser().parse_paramvalue(tuple_paramvalue)
            part_results.update([(tuple[0], tuple[2])])

        for x in xml.findall('.//VALUE.INSTANCEWITHPATH'):
            s = tostring(x)
            tt = pywbem.tupletree.xml_to_tupletree_sax(s, 'INSTANCEWITHPATH')
            # return instance path object
            part_res = TupleParser().parse_value_instancewithpath(tt)
            result_element = part_res

            specific_prop_name, _ = self.property_filter

            specific_prop = False
            if specific_prop_name and specific_prop_name in result_element:
                specific_prop = result_element[specific_prop_name]
            if specific_prop:
                specific_prop_value = None
                component_identifier = None
                if specific_prop_name in result_element:
                    specific_prop_value = str(result_element[specific_prop_name])
                if self.result_component_key in result_element:
                    component_identifier = result_element[
                        self.result_component_key
                    ]

                monitoring_result = {
                    self.classname: {
                        (specific_prop_name, specific_prop_value): {
                            (self.result_component_key, component_identifier):
                                result_element
                        }
                    }
                }

                extend_results(results_for_monitoring, monitoring_result)
            else:
                res.append(result_element)

        if results_for_monitoring:
            part_results.update({'IRETURNVALUE': results_for_monitoring})
        else:
            part_results.update({'IRETURNVALUE': res})
        return OpenEnumerateInstances._getResultParams(part_results)

    @staticmethod
    def _getResultParams(result):
        """Common processing for pull results to separate
           end-of-sequence, enum-context, and entities in IRETURNVALUE.
           Returns tuple of entities in IRETURNVALUE, end_of_sequence,
           and enumeration_context)
        """
        end_of_sequence = False
        enumeration_context = None

        sequence = result.get('EndOfSequence')
        if sequence and isinstance(sequence, six.string_types) and \
                sequence.lower() in ['true', 'false']:  # noqa: E125
            end_of_sequence = sequence.lower() == 'true'

        context = result.get('EnumerationContext')
        if context and isinstance(context, six.string_types):  # noqa: E125
            enumeration_context = context

        rtn_objects = result.get('IRETURNVALUE') or []

        if not sequence or not context:
            raise CIMError(
                CIM_ERR_INVALID_PARAMETER,
                "EndOfSequence or EnumerationContext required"
            )

        # convert enum context if eos is True
        # Otherwise, returns tuple of enumeration context and namespace
        rtn_ctxt = None if end_of_sequence else enumeration_context

        if rtn_ctxt:
            return (rtn_objects, end_of_sequence, rtn_ctxt)
        else:
            return rtn_objects


def extend_results(base_dict, value_for_update):
    """Update result dict with a nested dict."""
    for k, v in value_for_update.iteritems():
        if isinstance(v, dict):
            base_dict[k] = extend_results(
                base_dict.get(k, dict()), v
            )
        else:
            base_dict[k] = v
    return base_dict


class PullInstances(OpenEnumerateInstances):
    def __init__(self, creds, namespace, host, port, ssl, EnumerationContext,
                 MaxObjectCount, classname, **kwargs):
        self.classname = classname
        self.namespace = namespace
        self.cim_method = "PullInstancesWithPath"
        self.property_filter = (None, None)
        self.result_component_key = None

        if all(kwargs.get('PropertyFilter', self.property_filter)):
            self.property_filter = kwargs['PropertyFilter']

        if kwargs.get('ResultComponentKey'):
            self.result_component_key = kwargs['ResultComponentKey']

        payload = self.imethodcallPayload(
            self.cim_method,
            namespace,
            EnumerationContext=EnumerationContext,
            MaxObjectCount=MaxObjectCount
        )
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))
        url = self.build_url(ssl, host, port)
        if ssl:
            # TODO  build SSL factory
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

class EnumerateInstances(BaseWBEMMethod):
    """Factory to produce EnumerateInstances WBEM clients."""

    def __init__(self, creds, classname, host, port, ssl, namespace='root/cimv2', **kwargs):

        # create Endpoint
        # creaet Agent
        # run agent.request
        # add parse callback
        # return defered


        self.classname = classname
        self.namespace = namespace
        self.cim_method = "EnumerateInstances"
        payload = self.imethodcallPayload(
            self.cim_method,
            namespace,
            ClassName=CIMClassName(classname),
            **kwargs)
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))
        #check if ssl
        #create context fsctory for Agent
        url = self.build_url(ssl, host, port)
        if ssl:
            # TODO  build SSL factory
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s:%s) at 0x%x>' % \
               (self.__class__, self.namespace, self.classname, id(self))

    @staticmethod
    def parseResponse(xml):
        res = []
        for x in xml.findall('.//VALUE.NAMEDINSTANCE'):
            s = tostring(x)
            tt = pywbem.tupletree.xml_to_tupletree_sax(s, 'NAMEDINSTANCE')
            # returns CIMInstance
            r = TupleParser().parse_value_namedinstance(tt)
            res.append(r)
        return res

class EnumerateInstanceNames(BaseWBEMMethod):
    """Factory to produce EnumerateInstanceNames WBEM clients."""

    def __init__(self, creds, classname, host, port, ssl, namespace = 'root/cimv2', **kwargs):

        self.classname = classname
        self.namespace = namespace
        self.cim_method = "EnumerateInstanceNames"

        payload = self.imethodcallPayload(
            self.cim_method,
            namespace,
            ClassName=CIMClassName(classname),
            **kwargs)
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))
        # check if ssl
        # create context fsctory for Agent
        url = self.build_url(ssl, host, port)
        if ssl:
            # TODO  build SSL factory
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s:%s) at 0x%x>' % \
               (self.__class__, self.namespace, self.classname, id(self))

    def parseResponse(self, xml):

        tt = [pywbem.tupletree.xml_to_tupletree_sax(tostring(x), 'INSTANCENAME')
              for x in xml.findall('.//INSTANCENAME')]

        # returns CIMInstance
        names = [TupleParser().parse_instancename(x) for x in tt]

        [setattr(n, 'namespace', self.namespace) for n in names]

        return names

class EnumerateClassNames(BaseWBEMMethod):
    """Factory to produce EnumerateClassNames WBEM clients."""

    def __init__(self, creds, host, port, ssl, namespace = 'root/cimv2', **kwargs):

        self.namespace = namespace
        self.cim_method = "EnumerateClassNames"

        payload = self.imethodcallPayload(
            self.cim_method,
            self.namespace,
            **kwargs)
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))

        url = self.build_url(ssl, host, port)
        if ssl:
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s) at 0x%x>' % \
               (self.__class__, self.namespace, id(self))

    def parseResponse(self, xml):

        tt = [pywbem.tupletree.xml_to_tupletree_sax(tostring(x), 'CLASSNAME')
              for x in xml.findall('.//CLASSNAME')]

        # returns CIMInstance
        return [TupleParser().parse_classname(x) for x in tt]

class EnumerateClasses(BaseWBEMMethod):
    """Factory to produce EnumerateClasses WBEM clients."""

    def __init__(self, creds, host, port, ssl, namespace = 'root/cimv2', **kwargs):

        self.namespace = namespace
        self.cim_method = "EnumerateClasses"

        payload = self.imethodcallPayload(
            self.cim_method,
            self.namespace,
            **kwargs)
        headers = self.get_headers(creds, self.cim_method, self.namespace)
        body = FileBodyProducer(StringIO(str(payload)))

        url = self.build_url(ssl, host, port)
        if ssl:
            contextFactory = WBEMClientContextFactory()
            agent = Agent(reactor, contextFactory)

        else:
            agent = Agent(reactor)
        self.deferred = agent.request('POST', url, headers, body)
        self.deferred.addCallback(self.cbResponse)
        self.deferred.addCallback(self.parseErrorAndResponse)
        self.deferred.addCallback(self.parseResponse)
        self.deferred.addErrback(self.error)

    def __repr__(self):
        return '<%s(/%s) at 0x%x>' % \
               (self.__class__, self.namespace, id(self))

    def parseResponse(self, xml):

        tt = [pywbem.tupletree.xml_to_tupletree_sax(tostring(x), 'CLASS')
              for x in xml.findall('.//CLASS')]

        # returns CIMInstance
        return [TupleParser().parse_class(x) for x in tt]


