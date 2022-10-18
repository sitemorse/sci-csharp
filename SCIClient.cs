/*
 * Copyright 2020 Sitemorse Ltd. All rights reserved.
 * 
 */

/**
 * Implement the Sitemorse CMS Integration (SCI) Client protocol.
 * 
 * @author Sitemorse (UK Sales) Ltd
 * @version 1.2
 */
using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using System.Net.Security;

namespace com.sitemorse.sci
{
    public class SCIClient
    {
        #region Static Fields
        /**
         * The default hostname of the SCI server.
         */
        private static String SCI_DEFAULT_SERVER = "sci.sitemorse.com";
        /**
         * The default TCP port to connect to on the SCI server, when not using SSL.
         */
        private static int SCI_DEFAULT_PORT = 5371;
        /**
         * The default TCP port to connect to on the SCI server, when using SSL.
         */
        private static int SCI_DEFAULT_SSL_PORT = 5372;
        /* The default TCP port for an HTTP proxy server.*/
        private static int HTTP_PROXY_PORT = 3128;
        /**
         * The time-out when connecting to the SCI server, in milliseconds.
         */
        private static int SCI_CONNECT_TIMEOUT = 30 * 1000;
        /**
         * The time-out when reading from the SCI server, in milliseconds.
         */
        private static int SCI_READ_TIMEOUT = 240 * 1000;
        /**
         * The time-out for performing the web request, in milliseconds.
         */
        private static int WEB_TIMEOUT = 60 * 1000;
        /**
         * The buffer size to use when reading HTTP request/response bodies. This
         * needs to be small in order for the WEB_TIMEOUT to work properly.
         */
        private static int BUFFER_SIZE = 512;
        /**
         * Lines are ended by carriage-return then line-feed (0x0d 0x0a).
         */
        private static String CRLF = "\r\n";
        /**
         * We use ISO-8859-1 when reading and writing from sockets. This is because
         * it is an 8-bit single-byte character set and is a superset of US-ASCII,
         * but we don't actually ever treat top-bit-set bytes as any other than
         * opaque binary data.
         */
        private static String SCI_CHARSET = "iso-8859-1";
        /**
         * The Java identifier string for the HMAC-SHA1 algorithm that is used by
         * the SCI protocol authentication stage.
         */
        private static String SCI_HASH_ALGORITHM = "HmacSHA1";
        #endregion

        #region Property Fields
        /**
         * The host name of the SCI server.
         */
        private String _ServerHostname = null;
        /**
         * The TCP port number of the SCI server.
         */
        private int _ServerPort = 0;
        /**
         * Whether or not to use SSL to connect to the SCI server.
         */
        private bool _ServerSecure = true;
        /**
         * Whether or not we should allow HTTP POST requests to be proxied through
         * us.
         */
        private bool _PostAllowed = false;
        /**
         * The configured SCI licence key.
         */
        private String _LicenceKey = null;
        /**
 * The hostname of the HTTP proxy server to tunnel the SCI connection
 * through.
 */
        private String _SciProxyHostname = null;
        /**
         * The port number of the HTTP proxy server to tunnel the SCI connection
         * through.
         */
        private int _SciProxyPort = 0;
        /**
         * Extra headers to send with each request.
         */
        private String[] _ExtraHeaders = null;
        /**
         * Extra query string to send with each request.
         */
        private String _ExtraQuery = null;
        /**
         * User identifier used with non-legacy licence keys
         */
        private String _User = "";

        #endregion

        #region Constructors
        /**
         * Construct an SCIClient object with the specified licence key, and default
         * connection parameters.
         * 
         * @param licenceKey
         *            The SCI licence key.
         */
        public SCIClient(String licenceKey)
        {
            this._LicenceKey = licenceKey;
        }

        /**
         * Construct an SCIClient object with the specified licence key, using the
         * specified host name to connect to the SCI server.
         * 
         * @param licenceKey
         *            The SCI licence key.
         * @param serverHostname
         *            The host name to use to connect.
         */
        public SCIClient(String licenceKey, String serverHostname)
        {
            this._ServerHostname = serverHostname;
            this._LicenceKey = licenceKey;
        }

        /**
         * Construct an SCIClient object with the specified licence key, using the
         * specified host name and port to connect to the SCI server.
         * 
         * @param licenceKey
         *            The SCI licence key.
         * @param serverHostname
         *            The host name to use to connect.
         * @param serverPort
         *            The TCP port number to use to connect.
         */
        public SCIClient(String licenceKey, String serverHostname, int serverPort)
        {
            this._LicenceKey = licenceKey;
            this._ServerHostname = serverHostname;
            this._ServerPort = serverPort;
        }

        /**
         * Construct an SCIClient object with the specified licence key, using the
         * specified host name and port to connect to the SCI server, and setting
         * whether or not to use SSL to connect.
         * 
         * @param licenceKey
         *            The SCI licence key.
         * @param serverHostname
         *            The host name to use to connect.
         * @param serverPort
         *            The TCP port number to use to connect.
         * @param serverSecure
         *            true to use SSL when connecting to the SCI server.
         */
        public SCIClient(String licenceKey, String serverHostname, int serverPort,
                bool serverSecure)
        {
            this._LicenceKey = licenceKey;
            this._ServerHostname = serverHostname;
            this._ServerPort = serverPort;
            this._ServerSecure = serverSecure;
        }
        #endregion

        #region Public Properties

        /**
         * Get the host name used when connecting to the SCI server.
         * 
         * @return The host name used to connect to the SCI server.
         */
        public String ServerHostname
        {

            get
            {
                return (_ServerHostname == null) ? SCI_DEFAULT_SERVER : _ServerHostname;
            }
            set
            {
                _ServerHostname = value;
            }
        }



        /**
         * Get the TCP port number used when connecting to the SCI server.
         * 
         * @return The TCP port number to use.
         */
        public int ServerPort
        {
            get
            {
                if (_ServerPort != 0)
                    return _ServerPort;
                return _ServerSecure ? SCI_DEFAULT_SSL_PORT : SCI_DEFAULT_PORT;
            }
            set
            {
                _ServerPort = value;
            }
        }

        /**
         * Set whether or not the connection to the SCI server should use SSL.
         * 
         * @param serverSecure
         *            true if the connection to the SSL server should use SSL.
         */
        public bool ServerSecure
        {
            get
            {
                return _ServerSecure;
            }
            set
            {
                _ServerSecure = value;
            }
        }
        /**
         * Set whether or not HTTP POSTs are allowed to be proxied through us.
         * 
         * @param postAllowed
         *            true if POSTs should be allowed.
         */
        public bool PostAllowed
        {
            set
            {
                this._PostAllowed = value;
            }
            get
            {
                return _PostAllowed;
            }
        }

        /**
	 * Set the host name of the HTTP proxy server to tunnel the SCI connection
	 * through.
	 * 
	 * @param sciProxyHostname
	 *            the host name to use, or null to use no proxy.
	 */
        public string SciProxyHostname
        {
            get
            {
                return _SciProxyHostname;
            }
            set
            {
                this._SciProxyHostname = value;
            }

        }

        /**
         * Set the TCP port number of the HTTP proxy server to tunnel the SCI
         * connection through.
         * 
         * @param sciProxyPort
         *            the sciProxyPort to set
         */
        public int SciProxyPort
        {
            get
            {
                return _SciProxyPort == 0 ? HTTP_PROXY_PORT : _SciProxyPort;
            }
            set
            {
                _SciProxyPort = value;
            }
        }

        /**
         * Sets extra HTTP headers to send with each request that is proxied through
         * this class. Each string in the array should be an RFC-822-style header,
         * with no newline or carriage return at the end (e.g.
         * "Cookie: UserAuth=12345678").
         * 
         * @param extraHeaders
         *            the extra headers to send, or null to not send any
         */
        public String[] ExtraHeaders
        {
            get
            {
                return _ExtraHeaders;
            }
            set
            {
                _ExtraHeaders = value;
            }
        }

        /**
         * Sets an extra query string to be sent with each request that is proxied
         * through this class. The string should be simply the extra parameter(s) to
         * send, with no "?" or trailing or leading "&" (e.g. "a=b" or "a=b&c=d").
         * 
         * @param extraQuery
         *            the extra query string to send, or null to send none
         */
        public string ExtraQuery
        {
            get
            {
                return _ExtraQuery;
            }
            set
            {
                _ExtraQuery = value;
            }
        }

        public string User { get => _User; set => _User = value; }

        #endregion

        #region Public Methods
        /**
         * Perform a Sitemorse test of the specified URL. Only the specific host
         * name identified in the URL itself will be proxied, all other host names
         * will be connected to directly by the Sitemorse test server. The
         * "snapshot-view" version of the results will be used.
         * 
         * @param url
         *            The URL to test.
         * @return The URL of the finished report to display to the user.
         * @throws SCIException
         */
        public AssessmentResponse PerformTest(String url)
        {
            return PerformTest(url, "snapshot-page");
        }

        /**
         * Perform a Sitemorse test of the specified URL. Only the specific host
         * name identified in the URL itself will be proxied, all other host names
         * will be connected to directly by the Sitemorse test server.
         * 
         * @param url
         *            The URL to test.
         * @param view
         *            The view that should be displayed to the user when the test is
         *            complete. This must be one of "report", "snapshot-page" or
         *            "snapshot-source".
         * @return The URL of the finished report to display to the user.
         * @throws SCIException
         */
        public AssessmentResponse PerformTest(String url, String view)
        {
            String[] hostNames = new String[1];
            Uri urlobj;

            try
            {
                urlobj = new Uri(url);
            }
            catch (UriFormatException e)
            {
                throw new SCIException(e);
            }
            hostNames[0] = urlobj.Host;
            return PerformTest(url, hostNames, view);
        }

        /**
         * Perform a Sitemorse test of the specified URL. All the specified host
         * names will be proxied via the SCI client. Note that the host name
         * indicated by the URL should be included in the host names list. The
         * "snapshot-view" version of the results will be used.
         * 
         * @param url
         *            The URL to test.
         * @param hostNames
         *            An array of host names to proxy.
         * @return The URL of the finished report to display to the user.
         * @throws SCIException
         */
        public AssessmentResponse PerformTest(String url, String[] hostNames)
        {
            return PerformTest(url, hostNames, "snapshot-page");
        }

        /**
         * Perform a Sitemorse test of the specified URL. All the specified host
         * names will be proxied via the SCI client. Note that the host name
         * indicated by the URL should be included in the host names list.
         * 
         * @param url
         *            The URL to test.
         * @param hostNames
         *            An array of host names to proxy.
         * @param view
         *            The view that should be displayed to the user when the test is
         *            complete. This must be one of "report", "snapshot-page" or
         *            "snapshot-source".
         * @return The URL of the finished report to display to the user.
         * @throws SCIException
         */
        public AssessmentResponse PerformTest(String url, String[] hostNames, String view)
        {
            Socket sock = null;
            Stream sciStream;
            StreamReader sciIn;
            StreamWriter sciOut;
            String line;
            Encoding encoding;

            if (!(view.Equals("report") || view.Equals("snapshot-page") ||
                    view.Equals("snapshot-source")))
                throw new SCIException("Invalid 'view' parameter");
            try
            {
                encoding = Encoding.GetEncoding(SCI_CHARSET);
                if (_SciProxyHostname != null)
                {
                    sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                    sock.SendTimeout = SCI_CONNECT_TIMEOUT;
                    sock.ReceiveTimeout = SCI_CONNECT_TIMEOUT;
                    sock.Connect(SciProxyHostname, SciProxyPort);

                    sock.SendTimeout = SCI_READ_TIMEOUT;
                    sock.ReceiveTimeout = SCI_READ_TIMEOUT;

                    sciStream = new NetworkStream(sock);
                    sciIn = new StreamReader(sciStream, encoding);
                    sciOut = new StreamWriter(sciStream, encoding);

                    sciOut.Write("CONNECT " + ServerHostname + ":"
                            + ServerPort + " HTTP/1.0" + CRLF + CRLF);
                    sciOut.Flush();
                    line = sciIn.ReadLine();
                    if (line == null)
                        throw new SCIException("HTTP proxy dropped connection "
                                + "after request");
                    if (!line.StartsWith("HTTP/1.") || line.Length < 12)
                        throw new SCIException("Unknown status line "
                                + "from HTTP proxy: " + line);
                    if (!line.Substring(8, 4).Equals(" 200"))
                        throw new SCIException("HTTP proxy server returned "
                                + "error: " + line);
                    while (true)
                    {
                        line = sciIn.ReadLine();
                        if (line == null)
                            throw new SCIException("HTTP proxy dropped connection "
                                    + "during response headers");
                        if (line.Length == 0)
                            break;
                    }
                    if (ServerSecure)
                    {
                        SslStream sslStream = new SslStream(new NetworkStream(sock));
                        sslStream.AuthenticateAsClient(ServerHostname);
                        sciIn = new StreamReader(sslStream, encoding);
                        sciOut = new StreamWriter(sslStream, encoding);
                    }
                }
                else
                {
                    sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sock.SendTimeout = SCI_CONNECT_TIMEOUT;
                    sock.ReceiveTimeout = SCI_CONNECT_TIMEOUT;
                    sock.Connect(ServerHostname, ServerPort);

                    sock.SendTimeout = SCI_READ_TIMEOUT;
                    sock.ReceiveTimeout = SCI_READ_TIMEOUT;

                    if (_ServerSecure)
                    {
                        SslStream sslStream = new SslStream(new NetworkStream(sock));
                        sslStream.AuthenticateAsClient(ServerHostname);
                        sciStream = sslStream;
                    }
                    else
                    {
                        sciStream = new NetworkStream(sock);
                    }

                    sciIn = new StreamReader(sciStream, encoding);
                    sciOut = new StreamWriter(sciStream, encoding);
                }

                line = sciIn.ReadLine();
                if (line == null)
                    throw new SCIException("SCI server immediately disconnected");
                if (line.Length < 16 || !line.Substring(0, 4).Equals("SCI:"))
                    throw new SCIException("Bad greeting line from SCI server");
                if (!line.Substring(4, 1).Equals("1"))
                    throw new SCIException(
                            "SCI server is using incompatible protocol version");
                sciOut.Write(generateAuthResponse(line.Substring(8)) + CRLF);
                sciOut.Flush();
                line = sciIn.ReadLine();
                if (line == null)
                    throw new SCIException("SCI server disconnected"
                            + " after authentication sent");
                if (!line.Equals("OK"))
                    throw new SCIServerError(line);
                JObject jsonreq = new JObject
                {
                    {"url", url},
                    {"hostNames", new JArray(hostNames)}, 
                    {"view", view},
                    {"extendedResponse", true},
                    {"user", User}
                };
                line = jsonreq.ToString();
                sciOut.Write(line.Length + CRLF + line);
                sciOut.Flush();
                line = sciIn.ReadLine();
                if (line == null)
                    throw new SCIException("SCI server disconnected"
                            + " after request data sent");
                if (!line.Equals("OK"))
                    throw new SCIServerError(line);
                return ProxyRequests(sciIn, sciOut, hostNames);

            }
            catch (SocketException e)
            {
                throw new SCIException(e);
            }
            catch (IOException e)
            {
                throw new SCIException(e);
            }
            catch (Exception e)
            {
                throw new SCIException(e);
            }
            finally
            {
                if (sock != null)
                {
                    try
                    {
                        sock.Close();
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }
        #endregion

        #region Private Methods
        /**
         * Generates the SCI authentication response string, using the configured
         * licenceKey and the challenge from the SCI server.
         * 
         * @param challenge
         *            Challenge string from server.
         * @return Authentication response string.
         * @throws SCIException
         */
        private String generateAuthResponse(String challenge)
        {
            try
            {
                HMAC hmac;
                switch (SCI_HASH_ALGORITHM)
                {
                    case "HmacSHA1":
                        hmac = new HMACSHA1();
                        break;
                    default:
                        throw new Exception("Hash Algorithm not recognised");
                }

                Encoding encoding = Encoding.GetEncoding(SCI_CHARSET);

                hmac.Key = encoding.GetBytes(_LicenceKey.Substring(8));

                return _LicenceKey.Substring(0, 8)
                        + hexify(hmac.ComputeHash(encoding.GetBytes(challenge)));
            }
            catch (ArgumentNullException e)
            {
                throw new SCIException(e);
            }
        }

        /**
         * Convert an array of bytes into a lower-case hexadecimal string
         * representation.
         * 
         * @param bytes
         *            Byte array to convert.
         * @return String containing hexadecimal digits.
         */
        private String hexify(byte[] bytes)
        {
            StringBuilder s = new StringBuilder(bytes.Length * 2);
            char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
				'9', 'a', 'b', 'c', 'd', 'e', 'f' };

            for (int i = 0; i < bytes.Length; i++)
            {
                s.Append(hexChars[(bytes[i] >> 4) & 0x0f]);
                s.Append(hexChars[bytes[i] & 0x0f]);
            }
            return s.ToString();
        }

        /**
         * Implements the proxy phase of the SCI protocol. Repeatedly reads requests
         * from the SCI server, validates and fulfils them, and returns the results
         * to the server. Finishes when the server says the report is complete.
         * 
         * @param sciIn
         *            The reader for the SCI server socket.
         * @param sciOut
         *            The writer for the SCI server socket.
         * @param hostNames
         *            The collection of host names we will proxy for.
         * @return The URL of the finished report to display to the user.
         * @throws SCIException
         */
        private AssessmentResponse ProxyRequests(StreamReader sciIn, StreamWriter sciOut,
                String[] hostNames)
        {
            String line;
            Uri url;
            String method, httpVersion;
            List<String> headers;
            int i;
            long timetarget;
            long now;
            // int clen;
            long starttime = 0;
            long resptime = 0;
            long endtime = 0;
            String path;
            String status = "";
            StringBuilder data;
            char[] buf = new char[BUFFER_SIZE];

            Socket sock = null;
            Stream webStream = null;
            StreamReader webIn;
            StreamWriter webOut;
            Encoding encoding;

            try
            {
                encoding = Encoding.GetEncoding(SCI_CHARSET);
                while (true)
                {
                    /* Read a request line and see what it says */
                    line = sciIn.ReadLine();
                    if (line == null)
                        throw new SCIException("SCI server disconnected"
                                + " during proxy phase");
                    if (line.Equals("XSCI-NOOP"))
                    {
                        /* no-op (timeout prevention), do nothing */
                        continue;
                    }
                    else if (line.StartsWith("XSCI-COMPLETE "))
                    {
                        /* Test is complete, return the parameter as our result */
                        var uri =  line.Substring(14);
                        var assessmentResonse = ReadExtendedResponse(sciIn);
                        return new AssessmentResponse(uri,assessmentResonse.Item1, assessmentResonse.Item2);
                    }
                    else if (line.StartsWith("XSCI-ERROR "))
                    {
                        /* Fatal error, throw the parameter as an exception */
                        throw new SCIServerError(line.Substring(11));
                    }
                    else if (!line.StartsWith("GET ")
                          && !line.StartsWith("POST "))
                    {
                        throw new SCIException("Unknown SCI request: " + line);
                    }
                    /*
                     * It's an HTTP request, parse the request line and the URL, and
                     * read the headers.
                     */
                    i = line.IndexOf(" ");
                    method = line.Substring(0, i);
                    i = line.LastIndexOf(" ");
                    httpVersion = line.Substring(i + 1);
                    if (!httpVersion.StartsWith("HTTP/1.")
                            || httpVersion.Length != 8)
                        throw new SCIException("Unknown HTTP version: "
                                + httpVersion);
                    url = new Uri(line.Substring(method.Length + 1, i - (method.Length + 1)));
                    var response =  ReadExtendedResponse(sciIn);
                    headers = response.Item1;
                    data = response.Item2;

                    /* Security checks on the request */
                    if (method.Equals("POST") && !_PostAllowed)
                    {
                        sciOut.Write("XSCI accessdenied "
                                + "POST actions have been disallowed" + CRLF);
                        sciOut.Flush();
                        continue;
                    }
                    if (!url.Scheme.Equals("http")
                            && !url.Scheme.Equals("https"))
                    {
                        sciOut.Write("XSCI badscheme " + "URL scheme '"
                                + url.Scheme + "' not allowed" + CRLF);
                        sciOut.Flush();
                        continue;
                    }
                    for (i = 0; i < hostNames.Length; i++)
                    {
                        if (hostNames[i].Equals(url.Host, StringComparison.InvariantCultureIgnoreCase))
                            break;
                    }
                    if (i >= hostNames.Length)
                    {
                        sciOut.Write("XSCI accessdenied "
                                + "CMS proxy access denied to host '"
                                + url.Host + "'" + CRLF);
                        sciOut.Flush();
                        continue;
                    }
                    if (url.Port != -1
                            && (url.Port < 1 || url.Port > 65535
                                    || url.Port == 19 || url.Port == 25))
                    {
                        sciOut.Write("XSCI badport " + "Access denied to port "
                                + url.Port + CRLF);
                        sciOut.Flush();
                        continue;
                    }

                    /*
                     * Forward the request to the relevant web server. This entire
                     * section must not take longer than WEB_TIMEOUT ms.
                     */
                    try
                    {
                        timetarget = DateTime.Now.Ticks + WEB_TIMEOUT * TimeSpan.TicksPerMillisecond;
                        /* Connect to the server */
                        starttime = DateTime.Now.Ticks;

                        sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        sock.SendTimeout = WEB_TIMEOUT;
                        sock.ReceiveTimeout = WEB_TIMEOUT;
                        sock.Connect(url.Host, url.Port);

                        if (url.Scheme.Equals("https"))
                        {
                            SslStream sslStream = new SslStream(new NetworkStream(sock));
                            sslStream.AuthenticateAsClient(url.Host);
                            webStream = sslStream;
                        }
                        else
                        {
                            webStream = new NetworkStream(sock);
                        }

                        webIn = new StreamReader(webStream, encoding);
                        webOut = new StreamWriter(webStream, encoding);

                         /*
					     * Calculate the path to send in the request.
					     * We may need to add parameters if this.extraQuery is set.
					     */
                        path = url.PathAndQuery;
                        if (ExtraQuery != null && ExtraQuery.Length > 0)
                        {
                            if (url.Query == null)
                                path += "?" + ExtraQuery;
                            else if (url.Query.Length == 0)
                                path += ExtraQuery;
                            else
                                path += "&" + ExtraQuery;
                        }

                        /*
                             * Write the request line, the headers, and the body (if
                             * any)
                             */
                        webOut.Write(method + " " + path + " "
                                + httpVersion + CRLF);


                        for (i = 0; i < headers.Count; i++)
                            webOut.Write(headers[i] + CRLF);

                        if (ExtraHeaders != null)
                        {
                            for (i = 0; i < ExtraHeaders.Length; i++)
                                webOut.Write(ExtraHeaders[i] + CRLF);
                        }

                        webOut.Write(CRLF);
                        if (data != null)
                            webOut.Write(data.ToString());
                        webOut.Flush();

                        /*
                         * Wait for the status response line, then read the headers
                         */
                        now = DateTime.Now.Ticks;
                        if (now >= timetarget)
                            throw new TimeoutException();

                        sock.ReceiveTimeout = (int)((long)(timetarget - now) / TimeSpan.TicksPerMillisecond);
                        status = webIn.ReadLine();
                        resptime = DateTime.Now.Ticks;
                        if (status == null)
                        {
                            sciOut.Write("XSCI noeoh " + "No end-of-headers found"
                                    + CRLF);
                            continue;
                        }
                        if (!status.StartsWith("HTTP"))
                        {
                            sciOut.Write("XSCI badstatus Bad status line '" + line
                                    + "'" + CRLF);
                            continue;
                        }
                        now = DateTime.Now.Ticks;
                        if (now >= timetarget)
                            throw new TimeoutException();
                        headers = ReadHeaders(sock, webIn, (int)(timetarget - now));
                        if (headers == null)
                        {
                            sciOut.Write("XSCI noeoh " + "No end-of-headers found"
                                    + CRLF);
                            continue;
                        }
                        /*
                         * Read the response body, by reading all the data until the
                         * socket is closed by the other end.
                         */
                        data = new StringBuilder();
                        while (true)
                        {
                            now = DateTime.Now.Ticks;
                            if (now >= timetarget)
                                throw new TimeoutException();
                            sock.ReceiveTimeout = (int)((long)(timetarget - now) / TimeSpan.TicksPerMillisecond);
                            i = webIn.Read(buf, 0, BUFFER_SIZE);
                            if (i == 0)
                                break;
                            data.Append(buf, 0, i);
                        }
                        endtime = DateTime.Now.Ticks;
                    }
                    catch (TimeoutException)
                    {
                        sciOut.Write("XSCI timeout Timeout reading from web server"
                                + CRLF);
                        continue;
                    }
                    catch (SocketException e)
                    {
                        if (e.ErrorCode == (int)SocketError.ConnectionRefused)
                        {
                            sciOut.Write("XSCI connref Connection refused" + CRLF);
                            continue;
                        }
                        else if (e.ErrorCode == (int)SocketError.HostNotFound)
                        {
                            sciOut.Write("XSCI noaddr Unknown hostname" + CRLF);
                            continue;
                        }
                        else
                        {
                            sciOut.Write("XSCI exception " + e.Message + CRLF);
                        }
                    }
                    catch (IOException e)
                    {
                        sciOut.Write("XSCI exception " + e.Message + CRLF);
                        continue;
                    }
                    catch (Exception e)
                    {
                        sciOut.Write("XSCI exception " + e.Message + CRLF);
                        continue;
                    }

                    finally
                    {
                        if (sock != null)
                        {
                            try
                            {
                                sock.Close();
                            }
                            catch (IOException)
                            {
                            }
                        }
                        sock = null;
                        sciOut.Flush();
                    }
                    /*
                     * Forward the response headers and body back to the SCI server.
                     * Remove any Content-Length header that may already exist, and
                     * add a new one that we can guarantee to be correct.
                     */
                    sciOut.Write(status + CRLF);
                    for (i = 0; i < headers.Count; i++)
                    {
                        if (!headers[i].ToLower()
                                .StartsWith("content-length:"))
                            sciOut.Write(headers[i] + CRLF);
                    }
                    sciOut.Write("Content-Length: " + data.Length + CRLF);
                    sciOut.Write("X-SCI-Response: " + ((resptime - starttime) / TimeSpan.TicksPerMillisecond) + CRLF);
                    sciOut.Write("X-SCI-TotalTime: " + ((endtime - starttime) / TimeSpan.TicksPerMillisecond) + CRLF);
                    sciOut.Write(CRLF);
                    sciOut.Write(data.ToString());
                    sciOut.Flush();
                }
            }
            catch (IOException e)
            {
                throw new SCIException(e);
            }
        }

        private Tuple<List<string>,StringBuilder> ReadExtendedResponse(StreamReader sciIn)
        {
            char[] buf = new char[BUFFER_SIZE];
            
            int i;
            var headers = ReadHeaders(null, sciIn, 0);
            /* If there was a Content-Length header, read a body too. */
            var data = new StringBuilder();
            for (i = 0; i < headers.Count; i++)
            {
                if (!headers[i].ToLower()
                    .StartsWith("content-length:")) continue;
                var clen = int.Parse(headers[i].Substring(16));
                data = new StringBuilder(clen);
                while (clen > 0)
                {
                    i = sciIn.Read(buf, 0,
                        clen > BUFFER_SIZE ? BUFFER_SIZE : clen);
                    if (i == -1)
                        throw new SCIException("SCI server "
                                               + " disconnected while sending"
                                               + " HTTP body");
                    data.Append(buf, 0, i);
                    clen -= i;
                }
                break;
            }
            return Tuple.Create(headers,data);
        }

        /**
         * Reads a set of RFC 822-style headers from a stream. If the socket and a
         * time-out are also provided, it will ensure that the entire operation
         * takes place within that time-out - otherwise, socket may be null and the
         * time-out should be 0. Returns null if the socket closes before the
         * end-of-headers marker is reached.
         * 
         * @param sock
         *            The underlying socket being read from.
         * @param in
         *            The stream to read the data from.
         * @param timeout
         *            The time-out in milliseconds, or zero for no time-out.
         * @return An array of header strings.
         * @throws IOException
         */
        private List<String> ReadHeaders(Socket sock, StreamReader input,
                int timeout)
        {
            List<String> headers = new List<String>();
            StringBuilder buf = new StringBuilder();
            String line;
            long timetarget;
            long now;

            timetarget = DateTime.Now.Ticks + timeout * TimeSpan.TicksPerMillisecond;
            while (true)
            {
                if (timeout > 0)
                {
                    now = DateTime.Now.Ticks;
                    if (now >= timetarget)
                        throw new TimeoutException("Timeout reading headers");
                    sock.ReceiveTimeout = (int)((timetarget - now) / TimeSpan.TicksPerMillisecond);
                }
                line = input.ReadLine();
                if (line == null)
                    return null;
                if (line.Length == 0)
                {
                    if (buf.Length > 0)
                        headers.Add(buf.ToString());
                    return headers;
                }
                if (line.ToCharArray()[0] == ' ' || line.ToCharArray()[0] == '\t')
                {
                    buf.Append(line);
                }
                else
                {
                    if (buf.Length > 0)
                    {
                        headers.Add(buf.ToString());
                        buf = new StringBuilder();
                    }
                    buf.Append(line);
                }
            }
        }
        #endregion
    }

    public class AssessmentResponse
    {
        public string Uri { get; private set; }
        public List<string> Headers { get; private set; }
        public StringBuilder Body { get; private set; }

        public AssessmentResponse(string uri, List<string> headers, StringBuilder body)
        {
            Uri = uri;
            Headers = headers;
            Body = body;
        }
    }
}