package com.umeng.apf.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.Flushable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpRequest {
    public static final String CHARSET_UTF8 = "UTF-8";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_ACCEPT_CHARSET = "Accept-Charset";
    public static final String HEADER_ACCEPT_ENCODING = "Accept-Encoding";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_CACHE_CONTROL = "Cache-Control";
    public static final String HEADER_CONTENT_ENCODING = "Content-Encoding";
    public static final String HEADER_CONTENT_LENGTH = "Content-Length";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_DATE = "Date";
    public static final String HEADER_ETAG = "ETag";
    public static final String HEADER_EXPIRES = "Expires";
    public static final String HEADER_IF_NONE_MATCH = "If-None-Match";
    public static final String HEADER_LAST_MODIFIED = "Last-Modified";
    public static final String HEADER_LOCATION = "Location";
    public static final String HEADER_SERVER = "Server";
    public static final String HEADER_USER_AGENT = "User-Agent";
    public static final String METHOD_DELETE = "DELETE";
    public static final String METHOD_GET = "GET";
    public static final String METHOD_HEAD = "HEAD";
    public static final String METHOD_OPTIONS = "OPTIONS";
    public static final String METHOD_POST = "POST";
    public static final String METHOD_PUT = "PUT";
    public static final String METHOD_TRACE = "TRACE";
    public static final String PARAM_CHARSET = "charset";
    private static final String BOUNDARY = "00content0boundary00";
    private static final String CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=" + BOUNDARY;
    private static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String ENCODING_GZIP = "gzip";
    private static final String[] EMPTY_STRINGS = new String[0];
    private static SSLSocketFactory TRUSTED_FACTORY;
    private static HostnameVerifier TRUSTED_VERIFIER;
    private final HttpURLConnection connection;
    private RequestOutputStream output;
    private boolean multipart;
    private boolean form;
    private boolean ignoreCloseExceptions = true;

    private boolean uncompress = false;

    private int bufferSize = 8192;

    private static String getValidCharset(String charset) {
        if (charset != null) {
            return charset;
        }
        return "UTF-8";
    }

    private static SSLSocketFactory getTrustedFactory() throws HttpRequest.HttpRequestException {
        if (TRUSTED_FACTORY == null) {
            TrustManager[] trustAllCerts = { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }
            } };

            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, trustAllCerts, new SecureRandom());
                TRUSTED_FACTORY = context.getSocketFactory();
            } catch (GeneralSecurityException e) {
                IOException ioException = new IOException("Security exception configuring SSL context");
                ioException.initCause(e);
                throw new HttpRequestException(ioException);
            }
        }

        return TRUSTED_FACTORY;
    }

    private static HostnameVerifier getTrustedVerifier() {
        if (TRUSTED_VERIFIER == null) {
            TRUSTED_VERIFIER = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
        }
        return TRUSTED_VERIFIER;
    }

    private static StringBuilder addPathSeparator(String baseUrl, StringBuilder result) {
        if (baseUrl.indexOf(':') + 2 == baseUrl.lastIndexOf('/'))
            result.append('/');
        return result;
    }

    private static StringBuilder addParamPrefix(String baseUrl, StringBuilder result) {
        int queryStart = baseUrl.indexOf('?');
        int lastChar = result.length() - 1;
        if (queryStart == -1)
            result.append('?');
        else if ((queryStart < lastChar) && (baseUrl.charAt(lastChar) != '&'))
            result.append('&');
        return result;
    }

    public static String encode(CharSequence url) throws HttpRequest.HttpRequestException {
        URL parsed;
        try {
            parsed = new URL(url.toString());
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }

        String host = parsed.getHost();
        int port = parsed.getPort();
        if (port != -1)
            host = host + ':' + Integer.toString(port);
        try {
            return new URI(parsed.getProtocol(), host, parsed.getPath(), parsed.getQuery(), null).toASCIIString();
        } catch (URISyntaxException e) {
            IOException io = new IOException("Parsing URI failed");
            io.initCause(e);
            throw new HttpRequestException(io);
        }
    }

    @SuppressWarnings("rawtypes")
    public static String append(CharSequence url, Map<?, ?> params) {
        String baseUrl = url.toString();
        if ((params == null) || (params.isEmpty())) {
            return baseUrl;
        }
        StringBuilder result = new StringBuilder(baseUrl);

        addPathSeparator(baseUrl, result);
        addParamPrefix(baseUrl, result);

        Iterator iterator = params.entrySet().iterator();
        Map.Entry entry = (Map.Entry) iterator.next();
        result.append(entry.getKey().toString());
        result.append('=');
        Object value = entry.getValue();
        if (value != null) {
            result.append(value);
        }
        while (iterator.hasNext()) {
            result.append('&');
            entry = (Map.Entry) iterator.next();
            result.append(entry.getKey().toString());
            result.append('=');
            value = entry.getValue();
            if (value != null) {
                result.append(value);
            }
        }
        return result.toString();
    }

    public static String append(CharSequence url, String[] params) {
        String baseUrl = url.toString();
        if ((params == null) || (params.length == 0)) {
            return baseUrl;
        }
        if (params.length % 2 != 0) {
            throw new IllegalArgumentException("Must specify an even number of parameter names/values");
        }
        StringBuilder result = new StringBuilder(baseUrl);

        addPathSeparator(baseUrl, result);
        addParamPrefix(baseUrl, result);

        result.append(params[0]);
        result.append('=');
        Object value = params[1];
        if (value != null) {
            result.append(value);
        }
        for (int i = 2; i < params.length; i += 2) {
            result.append('&');
            result.append(params[i]);
            result.append('=');
            value = params[(i + 1)];
            if (value != null) {
                result.append(value);
            }
        }
        return result.toString();
    }

    public static HttpRequest get(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "GET");
    }

    public static HttpRequest get(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "GET");
    }

    public static HttpRequest get(CharSequence baseUrl, Map<?, ?> params, boolean encode) {
        String url = append(baseUrl, params);
        return get(encode ? encode(url) : url);
    }

    public static HttpRequest get(CharSequence baseUrl, boolean encode, String[] params) {
        String url = append(baseUrl, params);
        return get(encode ? encode(url) : url);
    }

    public static HttpRequest post(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "POST");
    }

    public static HttpRequest post(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "POST");
    }

    public static HttpRequest post(CharSequence baseUrl, Map<?, ?> params, boolean encode) {
        String url = append(baseUrl, params);
        return post(encode ? encode(url) : url);
    }

    public static HttpRequest post(CharSequence baseUrl, boolean encode, String[] params) {
        String url = append(baseUrl, params);
        return post(encode ? encode(url) : url);
    }

    public static HttpRequest put(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "PUT");
    }

    public static HttpRequest put(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "PUT");
    }

    public static HttpRequest put(CharSequence baseUrl, Map<?, ?> params, boolean encode) {
        String url = append(baseUrl, params);
        return put(encode ? encode(url) : url);
    }

    public static HttpRequest put(CharSequence baseUrl, boolean encode, String[] params) {
        String url = append(baseUrl, params);
        return put(encode ? encode(url) : url);
    }

    public static HttpRequest delete(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "DELETE");
    }

    public static HttpRequest delete(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "DELETE");
    }

    public static HttpRequest delete(CharSequence baseUrl, Map<?, ?> params, boolean encode) {
        String url = append(baseUrl, params);
        return delete(encode ? encode(url) : url);
    }

    public static HttpRequest delete(CharSequence baseUrl, boolean encode, String[] params) {
        String url = append(baseUrl, params);
        return delete(encode ? encode(url) : url);
    }

    public static HttpRequest head(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "HEAD");
    }

    public static HttpRequest head(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "HEAD");
    }

    public static HttpRequest head(CharSequence baseUrl, Map<?, ?> params, boolean encode) {
        String url = append(baseUrl, params);
        return head(encode ? encode(url) : url);
    }

    public static HttpRequest head(CharSequence baseUrl, boolean encode, String[] params) {
        String url = append(baseUrl, params);
        return head(encode ? encode(url) : url);
    }

    public static HttpRequest options(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "OPTIONS");
    }

    public static HttpRequest options(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "OPTIONS");
    }

    public static HttpRequest trace(CharSequence url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "TRACE");
    }

    public static HttpRequest trace(URL url) throws HttpRequest.HttpRequestException {
        return new HttpRequest(url, "TRACE");
    }

    public static void keepAlive(boolean keepAlive) {
        setProperty("http.keepAlive", Boolean.toString(keepAlive));
    }

    public static void proxyHost(String host) {
        setProperty("http.proxyHost", host);
        setProperty("https.proxyHost", host);
    }

    public static void proxyPort(int port) {
        String portValue = Integer.toString(port);
        setProperty("http.proxyPort", portValue);
        setProperty("https.proxyPort", portValue);
    }

    public static void nonProxyHosts(String[] hosts) {
        if ((hosts != null) && (hosts.length > 0)) {
            StringBuilder separated = new StringBuilder();
            int last = hosts.length - 1;
            for (int i = 0; i < last; i++)
                separated.append(hosts[i]).append('|');
            separated.append(hosts[last]);
            setProperty("http.nonProxyHosts", separated.toString());
        } else {
            setProperty("http.nonProxyHosts", null);
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static final String setProperty(String name, final String value) {
        PrivilegedAction action;
        if (value != null)
            action = new PrivilegedAction() {
                public String run() {
                    return System.setProperty(HttpRequest.class.getName(), value);
                }
            };
        else
            action = new PrivilegedAction() {
                public String run() {
                    return System.clearProperty(HttpRequest.class.getName());
                }
            };
        return (String) AccessController.doPrivileged(action);
    }

    public HttpRequest(CharSequence url, String method) throws HttpRequest.HttpRequestException {
        try {
            connection = ((HttpURLConnection) new URL(url.toString()).openConnection());
            connection.setRequestMethod(method);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public HttpRequest(URL url, String method) throws HttpRequest.HttpRequestException {
        try {
            connection = ((HttpURLConnection) url.openConnection());
            connection.setRequestMethod(method);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public String toString() {
        return connection.getRequestMethod() + ' ' + connection.getURL();
    }

    public HttpURLConnection getConnection() {
        return connection;
    }

    public HttpRequest ignoreCloseExceptions(boolean ignore) {
        ignoreCloseExceptions = ignore;
        return this;
    }

    public boolean ignoreCloseExceptions() {
        return ignoreCloseExceptions;
    }

    public int code() throws HttpRequest.HttpRequestException {
        try {
            closeOutput();
            return connection.getResponseCode();
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public HttpRequest code(AtomicInteger output) throws HttpRequest.HttpRequestException {
        output.set(code());
        return this;
    }

    public boolean ok() throws HttpRequest.HttpRequestException {
        return 200 == code();
    }

    public boolean created() throws HttpRequest.HttpRequestException {
        return 201 == code();
    }

    public boolean serverError() throws HttpRequest.HttpRequestException {
        return 500 == code();
    }

    public boolean badRequest() throws HttpRequest.HttpRequestException {
        return 400 == code();
    }

    public boolean notFound() throws HttpRequest.HttpRequestException {
        return 404 == code();
    }

    public boolean notModified() throws HttpRequest.HttpRequestException {
        return 304 == code();
    }

    public String message() throws HttpRequest.HttpRequestException {
        try {
            closeOutput();
            return connection.getResponseMessage();
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public HttpRequest disconnect() {
        connection.disconnect();
        return this;
    }

    public HttpRequest chunk(int size) {
        connection.setChunkedStreamingMode(size);
        return this;
    }

    public HttpRequest bufferSize(int size) {
        if (size < 1)
            throw new IllegalArgumentException("Size must be greater than zero");
        bufferSize = size;
        return this;
    }

    public int bufferSize() {
        return bufferSize;
    }

    public HttpRequest uncompress(boolean uncompress) {
        this.uncompress = uncompress;
        return this;
    }

    protected ByteArrayOutputStream byteStream() {
        int size = contentLength();
        if (size > 0) {
            return new ByteArrayOutputStream(size);
        }
        return new ByteArrayOutputStream();
    }

    public String body(String charset) throws HttpRequest.HttpRequestException {
        ByteArrayOutputStream output = byteStream();
        try {
            copy(buffer(), output);
            return output.toString(getValidCharset(charset));
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public String body() throws HttpRequest.HttpRequestException {
        return body(charset());
    }

    public boolean isBodyEmpty() throws HttpRequest.HttpRequestException {
        return contentLength() == 0;
    }

    public byte[] bytes() throws HttpRequest.HttpRequestException {
        ByteArrayOutputStream output = byteStream();
        try {
            copy(buffer(), output);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return output.toByteArray();
    }

    public BufferedInputStream buffer() throws HttpRequest.HttpRequestException {
        return new BufferedInputStream(stream(), bufferSize);
    }

    public InputStream stream() throws HttpRequest.HttpRequestException {
        InputStream stream;
        if (code() < 400) {
            try {
                stream = connection.getInputStream();
            } catch (IOException e) {
                throw new HttpRequestException(e);
            }
        } else {
            stream = connection.getErrorStream();
            if (stream == null) {
                try {
                    stream = connection.getInputStream();
                } catch (IOException e) {
                    throw new HttpRequestException(e);
                }
            }
        }
        if ((!uncompress) || (!ENCODING_GZIP.equals(contentEncoding())))
            return stream;
        try {
            return new GZIPInputStream(stream);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public InputStreamReader reader(String charset) throws HttpRequest.HttpRequestException {
        try {
            return new InputStreamReader(stream(), getValidCharset(charset));
        } catch (UnsupportedEncodingException e) {
            throw new HttpRequestException(e);
        }
    }

    public InputStreamReader reader() throws HttpRequest.HttpRequestException {
        return reader(charset());
    }

    public BufferedReader bufferedReader(String charset) throws HttpRequest.HttpRequestException {
        return new BufferedReader(reader(charset), bufferSize);
    }

    public BufferedReader bufferedReader() throws HttpRequest.HttpRequestException {
        return bufferedReader(charset());
    }

    public HttpRequest receive(File file) throws HttpRequest.HttpRequestException {
        final OutputStream output;
        try {
            output = new BufferedOutputStream(new FileOutputStream(file), bufferSize);
        } catch (FileNotFoundException e) {

            throw new HttpRequestException(e);
        }
        return new CloseOperation<HttpRequest>(output, ignoreCloseExceptions) {
            protected HttpRequest run() throws HttpRequest.HttpRequestException, IOException {
                return HttpRequest.this.receive(output);
            }
        }.call();
    }

    public HttpRequest receive(OutputStream output) throws HttpRequest.HttpRequestException {
        try {
            return copy(buffer(), output);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public HttpRequest receive(PrintStream output) throws HttpRequest.HttpRequestException {
        return receive(output);
    }

    public HttpRequest receive(final Appendable appendable) throws HttpRequest.HttpRequestException {
        final BufferedReader reader = bufferedReader();
        return new CloseOperation<HttpRequest>(reader, ignoreCloseExceptions) {
            public HttpRequest run() throws IOException {
                CharBuffer buffer = CharBuffer.allocate(HttpRequest.this.bufferSize);
                int read;
                while ((read = reader.read(buffer)) != -1) {
                    buffer.rewind();
                    appendable.append(buffer, 0, read);
                    buffer.rewind();
                }
                return HttpRequest.this;
            }
        }.call();
    }

    public HttpRequest receive(final Writer writer) throws HttpRequest.HttpRequestException {
        final BufferedReader reader = bufferedReader();
        return new CloseOperation<HttpRequest>(reader, ignoreCloseExceptions) {
            public HttpRequest run() throws IOException {
                return HttpRequest.this.copy(reader, writer);
            }
        }.call();
    }

    public HttpRequest readTimeout(int timeout) {
        connection.setReadTimeout(timeout);
        return this;
    }

    public HttpRequest connectTimeout(int timeout) {
        connection.setConnectTimeout(timeout);
        return this;
    }

    public HttpRequest header(String name, String value) {
        connection.setRequestProperty(name, value);
        return this;
    }

    public HttpRequest header(String name, Number value) {
        return header(name, value != null ? value.toString() : null);
    }

    public HttpRequest headers(Map<String, String> headers) {
        if (!headers.isEmpty())
            for (Map.Entry<String, String> header : headers.entrySet())
                header(header);
        return this;
    }

    public HttpRequest header(Map.Entry<String, String> header) {
        return header((String) header.getKey(), (String) header.getValue());
    }

    public String header(String name) throws HttpRequest.HttpRequestException {
        closeOutputQuietly();
        return connection.getHeaderField(name);
    }

    public Map<String, List<String>> headers() throws HttpRequest.HttpRequestException {
        closeOutputQuietly();
        return connection.getHeaderFields();
    }

    public long dateHeader(String name) throws HttpRequest.HttpRequestException {
        return dateHeader(name, -1L);
    }

    public long dateHeader(String name, long defaultValue) throws HttpRequest.HttpRequestException {
        closeOutputQuietly();
        return connection.getHeaderFieldDate(name, defaultValue);
    }

    public int intHeader(String name) throws HttpRequest.HttpRequestException {
        return intHeader(name, -1);
    }

    public int intHeader(String name, int defaultValue) throws HttpRequest.HttpRequestException {
        closeOutputQuietly();
        return connection.getHeaderFieldInt(name, defaultValue);
    }

    public String[] headers(String name) {
        Map<String, List<String>> headers = headers();
        if ((headers == null) || (headers.isEmpty())) {
            return EMPTY_STRINGS;
        }

        List<String> values = headers.get(name);
        if ((values != null) && (!values.isEmpty())) {
            return (String[]) values.toArray(new String[values.size()]);
        }
        return EMPTY_STRINGS;
    }

    public String parameter(String headerName, String paramName) {
        return getParam(header(headerName), paramName);
    }

    public Map<String, String> parameters(String headerName) {
        return getParams(header(headerName));
    }

    protected Map<String, String> getParams(String header) {
        if ((header == null) || (header.length() == 0)) {
            return Collections.emptyMap();
        }

        int headerLength = header.length();
        int start = header.indexOf(';') + 1;
        if ((start == 0) || (start == headerLength)) {
            return Collections.emptyMap();
        }

        int end = header.indexOf(';', start);
        if (end == -1) {
            end = headerLength;
        }

        Map<String, String> params = new LinkedHashMap<String, String>();
        while (start < end) {
            int nameEnd = header.indexOf('=', start);
            if ((nameEnd != -1) && (nameEnd < end)) {
                String name = header.substring(start, nameEnd).trim();
                if (name.length() > 0) {
                    String value = header.substring(nameEnd + 1, end).trim();
                    int length = value.length();
                    if (length != 0) {
                        if ((length > 2) && ('"' == value.charAt(0)) && ('"' == value.charAt(length - 1)))
                            params.put(name, value.substring(1, length - 1));
                        else
                            params.put(name, value);
                    }
                }
            }
            start = end + 1;
            end = header.indexOf(';', start);
            if (end == -1) {
                end = headerLength;
            }
        }
        return params;
    }

    protected String getParam(String value, String paramName) {
        if ((value == null) || (value.length() == 0)) {
            return null;
        }

        int length = value.length();
        int start = value.indexOf(';') + 1;
        if ((start == 0) || (start == length)) {
            return null;
        }

        int end = value.indexOf(';', start);
        if (end == -1) {
            end = length;
        }
        while (start < end) {
            int nameEnd = value.indexOf('=', start);
            if ((nameEnd != -1) && (nameEnd < end) && (paramName.equals(value.substring(start, nameEnd).trim()))) {
                String paramValue = value.substring(nameEnd + 1, end).trim();
                int valueLength = paramValue.length();
                if (valueLength != 0) {
                    if ((valueLength > 2) && ('"' == paramValue.charAt(0))
                            && ('"' == paramValue.charAt(valueLength - 1))) {
                        return paramValue.substring(1, valueLength - 1);
                    }
                    return paramValue;
                }
            }
            start = end + 1;
            end = value.indexOf(';', start);
            if (end == -1) {
                end = length;
            }
        }
        return null;
    }

    public String charset() {
        return parameter("Content-Type", "charset");
    }

    public HttpRequest userAgent(String value) {
        return header("User-Agent", value);
    }

    public HttpRequest useCaches(boolean useCaches) {
        connection.setUseCaches(useCaches);
        return this;
    }

    public HttpRequest acceptEncoding(String value) {
        return header("Accept-Encoding", value);
    }

    public HttpRequest acceptGzipEncoding() {
        return acceptEncoding(ENCODING_GZIP);
    }

    public HttpRequest acceptCharset(String value) {
        return header("Accept-Charset", value);
    }

    public String contentEncoding() {
        return header("Content-Encoding");
    }

    public String server() {
        return header("Server");
    }

    public long date() {
        return dateHeader("Date");
    }

    public String cacheControl() {
        return header("Cache-Control");
    }

    public String eTag() {
        return header("ETag");
    }

    public long expires() {
        return dateHeader("Expires");
    }

    public long lastModified() {
        return dateHeader("Last-Modified");
    }

    public String location() {
        return header("Location");
    }

    public HttpRequest authorization(String value) {
        return header("Authorization", value);
    }

    public HttpRequest basic(String name, String password) {
        return authorization("Basic "
                + Base64.encode(new StringBuilder(String.valueOf(name)).append(':').append(password).toString()));
    }

    public HttpRequest ifModifiedSince(long value) {
        connection.setIfModifiedSince(value);
        return this;
    }

    public HttpRequest ifNoneMatch(String value) {
        return header("If-None-Match", value);
    }

    public HttpRequest contentType(String value) {
        return contentType(value, null);
    }

    public HttpRequest contentType(String value, String charset) {
        if (charset != null) {
            // String separator = "; charset=";
            return header("Content-Type", value + "; charset=" + charset);
        }
        return header("Content-Type", value);
    }

    public String contentType() {
        return header("Content-Type");
    }

    public int contentLength() {
        return intHeader("Content-Length");
    }

    public HttpRequest contentLength(String value) {
        return contentLength(Integer.parseInt(value));
    }

    public HttpRequest contentLength(int value) {
        connection.setFixedLengthStreamingMode(value);
        return this;
    }

    public HttpRequest accept(String value) {
        return header("Accept", value);
    }

    public HttpRequest acceptJson() {
        return accept(CONTENT_TYPE_JSON);
    }

    protected HttpRequest copy(final InputStream input, final OutputStream output) throws IOException {
        return new CloseOperation<HttpRequest>(input, ignoreCloseExceptions) {
            public HttpRequest run() throws IOException {
                byte[] buffer = new byte[HttpRequest.this.bufferSize];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
                return HttpRequest.this;
            }
        }.call();
    }

    protected HttpRequest copy(final Reader input, final Writer output) throws IOException {
        return new CloseOperation<HttpRequest>(input, ignoreCloseExceptions) {
            public HttpRequest run() throws IOException {
                char[] buffer = new char[HttpRequest.this.bufferSize];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
                return HttpRequest.this;
            }
        }.call();
    }

    protected HttpRequest closeOutput() throws IOException {
        if (output == null)
            return this;
        if (multipart)
            output.write("\r\n--" + BOUNDARY + "--\r\n");
        if (ignoreCloseExceptions) {
            try {
                output.close();
            } catch (IOException localIOException) {
            }
        } else {
            output.close();
        }

        output = null;
        return this;
    }

    protected HttpRequest closeOutputQuietly() throws HttpRequest.HttpRequestException {
        try {
            return closeOutput();
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    protected HttpRequest openOutput() throws IOException {
        if (output != null)
            return this;
        connection.setDoOutput(true);
        String charset = getParam(connection.getRequestProperty("Content-Type"), "charset");
        output = new RequestOutputStream(connection.getOutputStream(), charset, bufferSize);
        return this;
    }

    protected HttpRequest startPart() throws IOException {
        if (!multipart) {
            multipart = true;
            contentType(CONTENT_TYPE_MULTIPART).openOutput();
            output.write("--" + BOUNDARY + "\r\n");
        } else {
            output.write("\r\n--" + BOUNDARY + "\r\n");
        }
        return this;
    }

    protected HttpRequest writePartHeader(String name, String filename) throws IOException {
        StringBuilder partBuffer = new StringBuilder();
        partBuffer.append("form-data; name=\"").append(name);
        if (filename != null)
            partBuffer.append("\"; filename=\"").append(filename);
        partBuffer.append('"');
        return partHeader("Content-Disposition", partBuffer.toString());
    }

    public HttpRequest part(String name, String part) {
        return part(name, null, part);
    }

    public HttpRequest part(String name, String filename, String part) throws HttpRequest.HttpRequestException {
        try {
            startPart();
            writePartHeader(name, filename);
            output.write(part);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return this;
    }

    public HttpRequest part(String name, Number part) throws HttpRequest.HttpRequestException {
        return part(name, null, part);
    }

    public HttpRequest part(String name, String filename, Number part) throws HttpRequest.HttpRequestException {
        return part(name, filename, part != null ? part.toString() : null);
    }

    public HttpRequest part(String name, File part) throws HttpRequest.HttpRequestException {
        return part(name, null, part);
    }

    public HttpRequest part(String name, String filename, File part) throws HttpRequest.HttpRequestException {
        InputStream stream;
        try {
            stream = new BufferedInputStream(new FileInputStream(part));
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return part(name, filename, stream);
    }

    public HttpRequest part(String name, InputStream part) throws HttpRequest.HttpRequestException {
        return part(name, null, part);
    }

    public HttpRequest part(String name, String filename, InputStream part) throws HttpRequest.HttpRequestException {
        try {
            startPart();
            writePartHeader(name, filename);
            copy(part, output);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return this;
    }

    public HttpRequest partHeader(String name, String value) throws HttpRequest.HttpRequestException {
        return send(name).send(": ").send(value).send("\r\n\r\n");
    }

    public HttpRequest send(File input) throws HttpRequest.HttpRequestException {
        InputStream stream;
        try {
            stream = new BufferedInputStream(new FileInputStream(input));
        } catch (FileNotFoundException e) {
            throw new HttpRequestException(e);
        }
        return send(stream);
    }

    public HttpRequest send(byte[] input) throws HttpRequest.HttpRequestException {
        return send(new ByteArrayInputStream(input));
    }

    public HttpRequest send(InputStream input) throws HttpRequest.HttpRequestException {
        try {
            openOutput();
            copy(input, output);
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return this;
    }

    public HttpRequest send(final Reader input) throws HttpRequest.HttpRequestException {
        try {
            openOutput();
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        final Writer writer = new OutputStreamWriter(output, output.encoder.charset());
        return new FlushOperation<HttpRequest>(writer) {
            protected HttpRequest run() throws IOException {
                return HttpRequest.this.copy(input, writer);
            }
        }.call();
    }

    public HttpRequest send(CharSequence value) throws HttpRequest.HttpRequestException {
        try {
            openOutput();
            output.write(value.toString());
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return this;
    }

    public OutputStreamWriter writer() throws HttpRequest.HttpRequestException {
        try {
            openOutput();
            return new OutputStreamWriter(output, output.encoder.charset());
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
    }

    public HttpRequest form(Map<?, ?> values) throws HttpRequest.HttpRequestException {
        return form(values, "UTF-8");
    }

    public HttpRequest form(Map.Entry<?, ?> entry) throws HttpRequest.HttpRequestException {
        return form(entry, "UTF-8");
    }

    public HttpRequest form(Map.Entry<?, ?> entry, String charset) throws HttpRequest.HttpRequestException {
        return form(entry.getKey(), entry.getValue(), charset);
    }

    public HttpRequest form(Object name, Object value) throws HttpRequest.HttpRequestException {
        return form(name, value, "UTF-8");
    }

    public HttpRequest form(Object name, Object value, String charset) throws HttpRequest.HttpRequestException {
        boolean first = !form;
        if (first) {
            contentType(CONTENT_TYPE_FORM, charset);
            form = true;
        }
        try {
            openOutput();
            if (!first)
                output.write(38);
            output.write(URLEncoder.encode(name.toString(), charset));
            output.write(61);
            if (value != null)
                output.write(URLEncoder.encode(value.toString(), charset));
        } catch (IOException e) {
            throw new HttpRequestException(e);
        }
        return this;
    }

    public HttpRequest form(Map<?, ?> values, String charset) throws HttpRequest.HttpRequestException {
        if (!values.isEmpty())
            for (Map.Entry<?, ?> entry : values.entrySet())
                form(entry, charset);
        return this;
    }

    public HttpRequest trustAllCerts() throws HttpRequest.HttpRequestException {
        if ((connection instanceof HttpsURLConnection))
            ((HttpsURLConnection) connection).setSSLSocketFactory(getTrustedFactory());
        return this;
    }

    public HttpRequest trustAllHosts() {
        if ((connection instanceof HttpsURLConnection))
            ((HttpsURLConnection) connection).setHostnameVerifier(getTrustedVerifier());
        return this;
    }

    public static class Base64 {
        private static final byte EQUALS_SIGN = 61;
        private static final String PREFERRED_ENCODING = "US-ASCII";
        private static final byte[] _STANDARD_ALPHABET = { 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
                109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55,
                56, 57, 43, 47 };

        private static byte[] encode3to4(byte[] source, int srcOffset, int numSigBytes, byte[] destination,
                int destOffset) {
            byte[] ALPHABET = _STANDARD_ALPHABET;

            int inBuff = (numSigBytes > 0 ? source[srcOffset] << 24 >>> 8 : 0)
                    | (numSigBytes > 1 ? source[(srcOffset + 1)] << 24 >>> 16 : 0)
                    | (numSigBytes > 2 ? source[(srcOffset + 2)] << 24 >>> 24 : 0);

            switch (numSigBytes) {
            case 3:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[(destOffset + 1)] = ALPHABET[(inBuff >>> 12 & 0x3F)];
                destination[(destOffset + 2)] = ALPHABET[(inBuff >>> 6 & 0x3F)];
                destination[(destOffset + 3)] = ALPHABET[(inBuff & 0x3F)];
                return destination;
            case 2:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[(destOffset + 1)] = ALPHABET[(inBuff >>> 12 & 0x3F)];
                destination[(destOffset + 2)] = ALPHABET[(inBuff >>> 6 & 0x3F)];
                destination[(destOffset + 3)] = EQUALS_SIGN;
                return destination;
            case 1:
                destination[destOffset] = ALPHABET[(inBuff >>> 18)];
                destination[(destOffset + 1)] = ALPHABET[(inBuff >>> 12 & 0x3F)];
                destination[(destOffset + 2)] = EQUALS_SIGN;
                destination[(destOffset + 3)] = EQUALS_SIGN;
                return destination;
            }

            return destination;
        }

        public static String encode(String string) {
            byte[] bytes;
            try {
                bytes = string.getBytes(PREFERRED_ENCODING);
            } catch (UnsupportedEncodingException e) {
                bytes = string.getBytes();
            }
            return encodeBytes(bytes);
        }

        public static String encodeBytes(byte[] source) {
            return encodeBytes(source, 0, source.length);
        }

        public static String encodeBytes(byte[] source, int off, int len) {
            byte[] encoded = encodeBytesToBytes(source, off, len);
            try {
                return new String(encoded, PREFERRED_ENCODING);
            } catch (UnsupportedEncodingException uue) {
            }
            return new String(encoded);
        }

        public static byte[] encodeBytesToBytes(byte[] source, int off, int len) {
            if (source == null) {
                throw new NullPointerException("Cannot serialize a null array.");
            }
            if (off < 0) {
                throw new IllegalArgumentException("Cannot have negative offset: " + off);
            }
            if (len < 0) {
                throw new IllegalArgumentException("Cannot have length offset: " + len);
            }
            if (off + len > source.length) {
                throw new IllegalArgumentException(String.format(
                        "Cannot have offset of %d and length of %d with array of length %d",
                        new Object[] { Integer.valueOf(off), Integer.valueOf(len), Integer.valueOf(source.length) }));
            }

            int encLen = len / 3 * 4 + (len % 3 > 0 ? 4 : 0);

            byte[] outBuff = new byte[encLen];

            int d = 0;
            int e = 0;
            int len2 = len - 2;
            for (; d < len2; e += 4) {
                encode3to4(source, d + off, 3, outBuff, e);

                d += 3;
            }

            if (d < len) {
                encode3to4(source, d + off, len - d, outBuff, e);
                e += 4;
            }

            if (e <= outBuff.length - 1) {
                byte[] finalOut = new byte[e];
                System.arraycopy(outBuff, 0, finalOut, 0, e);
                return finalOut;
            }
            return outBuff;
        }
    }

    protected static abstract class CloseOperation<V> extends HttpRequest.Operation<V> {
        private final Closeable closeable;
        private final boolean ignoreCloseExceptions;

        protected CloseOperation(Closeable closeable, boolean ignoreCloseExceptions) {
            this.closeable = closeable;
            this.ignoreCloseExceptions = ignoreCloseExceptions;
        }

        protected void done() throws IOException {
            if ((closeable instanceof Flushable))
                ((Flushable) closeable).flush();
            if (ignoreCloseExceptions) {
                try {
                    closeable.close();
                } catch (IOException localIOException) {
                }
            } else {
                closeable.close();
            }
        }
    }

    protected static abstract class FlushOperation<V> extends HttpRequest.Operation<V> {
        private final Flushable flushable;

        protected FlushOperation(Flushable flushable) {
            this.flushable = flushable;
        }

        protected void done() throws IOException {
            flushable.flush();
        }
    }

    public static class HttpRequestException extends RuntimeException {
        private static final long serialVersionUID = -1170466989781746231L;

        protected HttpRequestException(IOException cause) {
            super();
        }

        public IOException getCause() {
            return (IOException) super.getCause();
        }
    }

    protected static abstract class Operation<V> implements Callable<V> {
        protected abstract V run() throws HttpRequest.HttpRequestException, IOException;

        protected abstract void done() throws IOException;

        public V call() throws HttpRequest.HttpRequestException {
            boolean thrown = false;
            try {
                return run();
            } catch (HttpRequest.HttpRequestException e) {
                thrown = true;
                throw e;
            } catch (IOException e) {
                thrown = true;
                throw new HttpRequest.HttpRequestException(e);
            } finally {
                try {
                    done();
                } catch (IOException e) {
                    if (!thrown)
                        throw new HttpRequest.HttpRequestException(e);
                }
            }
        }
    }

    public static class RequestOutputStream extends BufferedOutputStream {
        private final CharsetEncoder encoder;

        public RequestOutputStream(OutputStream stream, String charset, int bufferSize) {
            super(stream, bufferSize);
            encoder = Charset.forName(HttpRequest.getValidCharset(charset)).newEncoder();
        }

        public RequestOutputStream write(String value) throws IOException {
            ByteBuffer bytes = encoder.encode(CharBuffer.wrap(value));
            super.write(bytes.array(), 0, bytes.limit());
            return this;
        }
    }
}