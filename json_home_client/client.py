"""Classes for a Client that understands JSON home pages."""

import base64
import collections
import http
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, ClassVar, Dict, List, Mapping, Optional, Sequence, Tuple, Union, cast

import pkg_resources

from uri_template import URITemplate


def _indent(value: Any, name: str = None, pad: str = '  ') -> Sequence[str]:
	if (not value):
		return []
	if ((not isinstance(value, str)) and (not isinstance(value, collections.abc.Iterable))):
		value = repr(value)
	if (isinstance(value, str)):
		value = value.split('\n')
		if (1 == len(value)):
			return [pad + ((name + ': ') if (name) else '') + value[0]]
	output = [pad + name + ': '] if (name) else []
	if (isinstance(value, collections.abc.Mapping)):
		for name, item in value.items():
			output += _indent(item or 'None', name=name, pad=pad + ('  ' if (name) else ''))
	else:
		for item in value:
			output += _indent(item, name=None, pad=pad + ('  ' if (name) else ''))
	return output


class NetworkError(Exception):
	"""Exception raised for general network errors."""

	http_code: Optional[int]

	def __init__(self, message: Union[str, BaseException], http_code: int = None) -> None:
		self.http_code = http_code
		if (http_code):
			Exception.__init__(self, "HTTP error {code}: {reason}".format(code=http_code, reason=message))
		else:
			Exception.__init__(self, "Network error: {reason}".format(reason=message))


class MimeType:
	"""Parse a MIME type into it's components."""

	HOME_JSON: ClassVar['MimeType']
	JSON_HOME: ClassVar['MimeType']
	JSON: ClassVar['MimeType']
	JSON_PATCH: ClassVar['MimeType']
	FORM_URL_ENCODED: ClassVar['MimeType']

	type: str
	structure: Optional[str]
	subtype: Optional[str]

	def __init__(self, mime_type: str = None, type: str = None, structure: str = None, subtype: str = None) -> None:
		if (mime_type):
			self.type = mime_type
			self.subtype = None
			self.structure = None

			if ('/' in mime_type):
				self.type, rest = mime_type.split('/', 1)
				if ('+' in rest):
					self.subtype, self.structure = rest.split('+', 1)
				else:
					self.structure = rest
		else:
			self.type = type if (type) else ''
			self.structure = structure
			self.subtype = subtype

	def __eq__(self, other: Any) -> bool:
		"""Test equality."""
		if (isinstance(other, MimeType)):
			return ((self.type == other.type) and (self.structure == other.structure) and (self.subtype == other.subtype))
		return (str(self) == str(other))

	def __str__(self) -> str:
		"""Convert to string."""
		return (self.type + (('/' + ((self.subtype + '+' + self.structure) if (self.subtype) else self.structure)) if (self.structure) else ''))

	def __repr__(self) -> str:
		"""Debug dump."""
		return '[MimeType: {type} {structure}{subtype}]'.format(type=self.type,
																structure=self.structure,
																subtype=(' ' + self.subtype) if (self.subtype) else '')


MimeType.HOME_JSON = MimeType('application/home+json')
MimeType.JSON_HOME = MimeType('application/json-home')
MimeType.JSON = MimeType('application/json')
MimeType.JSON_PATCH = MimeType('application/json-patch')
MimeType.FORM_URL_ENCODED = MimeType('application/x-www-form-urlencoded')


class Response:
	"""Response from a request."""

	status_code: int
	headers: Mapping[str, Any]
	data: Any

	def __init__(self, response: Any) -> None:
		self.status_code = response.getcode()
		self.headers = response.info()
		self.data = response.read() if (200 == response.status) else None

		if (self.data and (('json' == self.content_type.structure) or ('json-home' == self.content_type.structure))):
			try:
				self.data = json.loads(self.data, object_pairs_hook=collections.OrderedDict)
			except Exception:
				pass

	@property
	def content_type(self) -> MimeType:
		"""Get content-type of response."""
		content_type = cast(str, self.headers.get('content-type'))
		return MimeType(content_type.split(';')[0]) if (content_type and (';' in content_type)) else MimeType(content_type)

	@property
	def encoding(self) -> str:
		"""Get encoding of response."""
		content_type = self.headers.get('content-type') if (self.headers) else None
		if (content_type and (';' in content_type)):
			encoding = content_type.split(';', 1)[1]
			if ('=' in encoding):
				return encoding.split('=', 1)[1].strip()
		return 'utf-8'


def _get(keys: Union[str, Sequence[str]], map: Mapping[str, Any], default: Any = None) -> Any:
	if (isinstance(keys, str)):
		keys = [keys, re.sub('[A-Z]', lambda match: '-' + match.group(0).lower(), keys)]
	for key in keys:
		if (key in map):
			return map[key]
	return default


class Hints:
	"""JSON-Home page Hints."""

	http_methods: Sequence[str]
	formats: Mapping[str, Sequence[MimeType]]
	ranges: Optional[Sequence[str]]
	preferences: Optional[Sequence[str]]
	preconditions: Optional[Sequence[str]]
	auth: Optional[Sequence[Mapping[str, str]]]
	docs: Optional[str]
	status: Optional[str]

	def __init__(self, data: Mapping[str, Any]) -> None:
		self.http_methods = [method.upper() for method in data['allow'] if method] if ('allow' in data) else ['GET']
		self.formats = {}
		formats = [MimeType(format) for format in data['formats']] if ('formats' in data) else []
		if (formats):
			if ('GET' in self.http_methods):
				self.formats['GET'] = formats

		if (('PATCH' in self.http_methods) and _get('acceptPatch', data)):
			self.formats['PATCH'] = [MimeType(format) for format in _get('acceptPatch', data)]
		if (('POST' in self.http_methods) and _get('acceptPost', data)):
			self.formats['POST'] = [MimeType(format) for format in _get('acceptPost', data)]
		if (('PUT' in self.http_methods) and _get('acceptPut', data)):
			self.formats['PUT'] = [MimeType(format) for format in _get('acceptPut', data)]

		self.ranges = _get('acceptRanges', data)
		self.preferences = _get('acceptPrefer', data)
		self.preconditions = _get(('preconditionRequired', 'precondition-req'), data)
		self.auth = _get(('authSchemes', 'auth-req'), data)
		self.docs = data.get('docs')
		self.status = data.get('status')

	def __repr__(self) -> str:
		"""Debug dump."""
		output: List[str] = []
		output += _indent(self.http_methods, 'HTTP Methods', pad='')
		output += _indent(self.formats, 'Formats', pad='')
		output += _indent(self.ranges, 'Ranges', pad='')
		output += _indent(self.preferences, 'Preferences', pad='')
		output += _indent(self.preconditions, 'Preconditions', pad='')
		output += _indent(self.auth, 'Auth', pad='')
		output += _indent(self.docs, 'Docs', pad='')
		output += _indent(self.status, 'Status', pad='')
		return '\n'.join(output)


class Resource:
	"""API resource class."""

	template: URITemplate
	variables: Mapping[str, str]
	hints: Optional[Hints]

	def __init__(self, base_url: str, url: str, variables: Mapping[str, str] = None, hints: Hints = None) -> None:
		try:
			self.template = URITemplate(urllib.parse.urljoin(base_url, url))
			if (variables):
				self.variables = {variable: urllib.parse.urljoin(base_url, variables[variable]) for variable in variables}
			else:
				self.variables = {variable.name: '' for variable in self.template.variables}
			self.hints = hints
		except Exception:
			self.template = URITemplate('')
			self.variables = {}
			self.hints = None

	def __repr__(self) -> str:
		"""Debug dump."""
		output = ['Resource:']
		output += _indent(self.template, 'Template')
		output += _indent(self.variables, 'Variables')
		output += _indent(self.hints, 'Hints')
		return '\n'.join(output)


class HTTPSConnection(http.client.HTTPSConnection):
	"""Subclass of HTTPSConnection to facilitate setting SNI."""

	_context: Optional[ssl.SSLContext]
	_sni_hostname: Optional[str]
	sock: Optional[socket.socket]
	source_address: Tuple[Union[bytearray, bytes, str], int]

	def __init__(self, host: str, port: int = None, context: ssl.SSLContext = None,
				 sni_hostname: str = None, **kwargs) -> None:
		http.client.HTTPSConnection.__init__(self, host=host, port=port, context=context, **kwargs)
		self._context = context
		self._sni_hostname = sni_hostname

	def connect(self) -> None:
		"""Make connection, setting SNI."""
		sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
		server_hostname = self._sni_hostname if self._sni_hostname else self.host
		if (self._context):
			self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


class HTTPSHandler(urllib.request.HTTPSHandler):
	"""Subclass of HTTPSHandler to facilitate setting SNI."""

	def __init__(self, context: ssl.SSLContext = None, sni_hostname: str = None, **kwargs) -> None:
		urllib.request.HTTPSHandler.__init__(self, context=context, **kwargs)
		self._context = context
		self._sni_hostname = sni_hostname

	def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
		"""Override https_open to get custom connection class."""
		return self.do_open(self.get_connection, req)

	def get_connection(self, host: str, port: int = None, timeout: float = 300,
					   source_address: Tuple[str, int] = None, blocksize: int = 8192,
					   **kwargs) -> HTTPSConnection:
		"""Factory function to create connections."""
		return HTTPSConnection(host=host, port=port, timeout=timeout, context=self._context,
							   sni_hostname=self._sni_hostname, source_address=source_address, **kwargs)


class Request(urllib.request.Request):
	"""Subclass of Request to allow setting TLS options."""

	sni_hostname: Optional[str]
	client_cert_path: Optional[str]
	client_key_path: Optional[str]
	ca_cert_path: Optional[str]

	def __init__(self, url: str, sni_hostname: str = None,
				 client_cert_path: str = None, client_key_path: str = None, ca_cert_path: str = None, **kwargs) -> None:
		urllib.request.Request.__init__(self, url, **kwargs)
		self.sni_hostname = sni_hostname
		self.client_cert_path = client_cert_path
		self.client_key_path = client_key_path
		self.ca_cert_path = ca_cert_path

	def open(self) -> Any:
		"""Override open to setup SSLContext and use custom opener."""
		context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		if (self.client_key_path and self.client_cert_path):
			context.load_cert_chain(self.client_cert_path, self.client_key_path)
		if (self.ca_cert_path):
			context.load_verify_locations(cafile=self.ca_cert_path)
		else:
			context.load_default_certs()
		context.verify_mode = ssl.CERT_REQUIRED
		context.check_hostname = True

		opener = urllib.request.build_opener(HTTPSHandler(context=context, sni_hostname=self.sni_hostname))
		return opener.open(self)


class Client:
	"""Client class to call JSON-Home APIs."""

	_base_url: str
	_sni_hostname: Optional[str]
	_client_cert_path: Optional[str]
	_client_key_path: Optional[str]
	_ca_cert_path: Optional[str]
	default_version: Optional[str]
	default_accept: MimeType
	username: Optional[str]
	password: Optional[str]
	user_agent: str
	_resources: Dict[str, 'Resource']
	_versions: Dict[str, str]
	_accepts: Dict[str, Sequence[MimeType]]

	def __init__(self, base_url: str, version: str = None, username: str = None, password: str = None, user_agent: str = None,
				 sni_hostname: str = None, client_cert_path: str = None, client_key_path: str = None, ca_cert_path: str = None) -> None:
		self._base_url = base_url
		self._sni_hostname = sni_hostname
		self._client_cert_path = client_cert_path
		self._client_key_path = client_key_path
		self._ca_cert_path = ca_cert_path

		self.default_version = version
		self.default_accept = MimeType.JSON
		self.username = username
		self.password = password
		self.user_agent = user_agent if (user_agent) else ('json_home_client/' + self.package_version)

		self._resources = {}
		self._versions = {}
		self._accepts = {}
		self._load_home()

	@property
	def package_version(self) -> str:
		"""Get version of package."""
		try:
			return pkg_resources.get_distribution('json_home_client').version
		except Exception:
			return '0.0.0'

	@property
	def base_url(self) -> str:
		"""Get base_url."""
		return self._base_url

	@base_url.setter
	def base_url(self, value: str) -> None:
		"""Set base_url and reload home page."""
		self._base_url = value
		self._load_home()

	def _load_home(self) -> None:
		home = self._request(self.base_url, accept=(MimeType.HOME_JSON, MimeType.JSON_HOME, MimeType.JSON))
		if (MimeType.JSON == home.content_type):
			for name in home.data:
				api_key = urllib.parse.urljoin(self.base_url, name)
				self._resources[api_key] = Resource(self.base_url, home.data[name])
		elif ((MimeType.HOME_JSON == home.content_type) or (MimeType.JSON_HOME == home.content_type)):
			resources = home.data.get('resources', {})
			for name in resources:
				api_key = urllib.parse.urljoin(self.base_url, name)
				data = resources[name]
				url = data['href'] if ('href' in data) else _get('hrefTemplate', data)
				variables = _get('hrefVars', data)
				hints = Hints(data['hints']) if ('hints' in data) else None
				self._resources[api_key] = Resource(self.base_url, url, variables, hints)

	def _relative_url(self, url: str) -> str:
		if (url.startswith(self.base_url)):
			relative = url[len(self.base_url):]
			if (relative.startswith('/') and not self.base_url.endswith('/')):
				relative = relative[1:]
			return relative
		return url

	@property
	def resource_names(self) -> Sequence[str]:
		"""Get names of API resources."""
		return [self._relative_url(api_key) for api_key in self._resources]

	def resource(self, name: str) -> Optional[Resource]:
		"""Get API resource."""
		return self._resources.get(urllib.parse.urljoin(self.base_url, name))

	def add_resource(self, name: str, url: str) -> None:
		"""Add a Resource URL."""
		resource = Resource(self.base_url, url)
		api_key = urllib.parse.urljoin(self.base_url, name)
		self._resources[api_key] = resource

	def _request(self, url: str, method: str = 'GET',
				 payload: bytes = None, content_type: MimeType = None,
				 accept: Sequence[MimeType] = None) -> Response:
		"""General purpose request."""
		request = Request(url=url, sni_hostname=self._sni_hostname,
						  client_cert_path=self._client_cert_path, client_key_path=self._client_key_path,
						  ca_cert_path=self._ca_cert_path,
						  data=payload, method=method)
		if ((payload is not None) and content_type):
			request.add_header('Content-Type', str(content_type))
		if (accept):
			request.add_header('Accept', ', '.join([str(mime_type) for mime_type in accept]))
		if (self.username and self.password):
			request.add_header('Authorization', 'Basic ' + base64.b64encode((self.username + ':' + self.password).encode('utf-8')).decode('ascii'))
		request.add_header('User-Agent', self.user_agent)

		try:
			with request.open() as response:
				return Response(response)
		except urllib.error.HTTPError as error:
			raise NetworkError(error.reason, error.code)
		except urllib.error.URLError as error:
			raise NetworkError(error.reason)
		except Exception as error:
			raise NetworkError(str(error))

	def _call(self, method: str, name: str, arguments: Mapping[str, Any], payload: bytes = None, content_type: MimeType = None) -> Optional[Response]:
		api_key = urllib.parse.urljoin(self.base_url, name)
		resource = self._resources.get(api_key)

		if (resource):
			url = resource.template.expand(**arguments)
			if (url):
				version = self._versions.get(api_key, self.default_version)
				if (version):
					accept: Sequence[MimeType] = [MimeType(type=mime_type.type, structure=mime_type.structure, subtype=version)
												  for mime_type in self._accepts.get(api_key, [self.default_accept])]
				else:
					accept = self._accepts.get(api_key, [self.default_accept])
				return self._request(url=url, method=method, payload=payload, content_type=content_type, accept=accept)
		return None

	def set_version(self, name: str, version: str = None) -> None:
		"""Set accept version for resource."""
		api_key = urllib.parse.urljoin(self.base_url, name)
		if (version):
			self._versions[api_key] = version
		else:
			del self._versions[api_key]

	def set_accept(self, name: str, content_type: Union[MimeType, Sequence[MimeType]]) -> None:
		"""Set accept types for resource."""
		api_key = urllib.parse.urljoin(self.base_url, name)
		self._accepts[api_key] = [content_type] if (isinstance(content_type, MimeType)) else content_type

	def get(self, name: str, **kwargs) -> Optional[Response]:
		"""Make a GET call to a resource."""
		return self._call('GET', name, kwargs)

	def post(self, name: str, payload: bytes = None, content_type: MimeType = None, **kwargs) -> Optional[Response]:
		"""Make a POST call to a resource."""
		return self._call('POST', name, kwargs, payload, content_type)

	def post_form(self, name: str, payload: Mapping[str, Any], **kwargs) -> Optional[Response]:
		"""Make a POST call to a resource with payload URL form encoded."""
		return self._call('POST', name, kwargs, urllib.parse.urlencode(payload).encode('utf-8'), MimeType.FORM_URL_ENCODED)

	def post_json(self, name: str, payload: Any = None, **kwargs) -> Optional[Response]:
		"""
		Make a POST call to a resource with JSON content.

		payload will be converted to JSON.
		"""
		return self._call('POST', name, kwargs, payload=json.dumps(payload).encode('utf-8'), content_type=MimeType.JSON)

	def put(self, name: str, payload: bytes = None, content_type: MimeType = None, **kwargs) -> Optional[Response]:
		"""Make a PUT call to a resource."""
		return self._call('PUT', name, kwargs, payload=payload, content_type=content_type)

	def patch(self, name: str, patch: Mapping[str, Any] = None, content_type: MimeType = MimeType.JSON_PATCH, **kwargs) -> Optional[Response]:
		"""
		Make a PATCH call to a resource.

		patch will be converted to JSON.
		"""
		return self._call('PATCH', name, kwargs, payload=json.dumps(patch).encode('utf-8'), content_type=content_type)

	def delete(self, name: str, **kwargs) -> Optional[Response]:
		"""Make a DELETE call to a resource."""
		return self._call('DELETE', name, kwargs)

	def __repr__(self) -> str:
		"""Debug dump."""
		output = ['Client:']
		output += _indent(self._base_url, 'Base URL')
		output += _indent(self.default_version, 'Default Version')
		output += _indent(self.default_accept, 'Default Accept')
		output += _indent(self.username, 'Username')
		output += _indent(self.password, 'Password')
		output += _indent(self.user_agent, 'User Agent')
		output += _indent(self._resources, 'Resources')
		output += _indent(self._versions, 'Versions')
		output += _indent(self._accepts, 'Accepts')
		return '\n'.join(output)
