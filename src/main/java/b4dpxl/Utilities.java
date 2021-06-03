package b4dpxl;

import burp.*;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Random;

public class Utilities {

    private static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private static boolean debug = false;

    public Utilities(final IBurpExtenderCallbacks _callbacks) {
        this(_callbacks, false);
    }

    public Utilities(final IBurpExtenderCallbacks _callbacks, boolean _debug) {
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        debug = _debug;
    }

    public static void debug(String _message) {
        if (debug) {
            callbacks.printOutput(_message);
        }
    }
    public static void debug(Object _obj) {
        if (debug) {
            callbacks.printOutput(_obj.toString());
        }
    }
    public static void println(String _message) {
        callbacks.printOutput(_message);
    }
    public static void println(Object _obj) {
        callbacks.printOutput(_obj.toString());
    }
    public static void err(String _message) {
        callbacks.printError(_message);
    }
    public static void err(String _message, Exception _e) {
        callbacks.printError(_message);
        _e.printStackTrace(stderr);
    }

    public static void alert(String _message) {
        JOptionPane.showMessageDialog(null,
                _message,
                "Error",
                JOptionPane.ERROR_MESSAGE
        );
    }
    public static void alert(String _message, Exception _e) {
        JOptionPane.showMessageDialog(null,
                _message + "\n\n" + _e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE
        );
        _e.printStackTrace(stderr);
    }

    public static URL getURL(IScanIssue _issue) throws MalformedURLException {
        URL url = _issue.getUrl();
        if (
                (url.getProtocol().equalsIgnoreCase("HTTPS") && url.getPort() == 443) ||
                        (url.getProtocol().equalsIgnoreCase("HTTP") && url.getPort() == 80)
        ) {
            url = new URL(url.getProtocol(), url.getHost(), url.getPath());
        }
        return url;
    }

    public static String getResponse(IScanIssue _issue) {
        IHttpRequestResponse requestResponse = _issue.getHttpMessages()[0];
        byte[] response = requestResponse.getResponse();
        return new String(Arrays.copyOfRange(
                response,
                helpers.analyzeResponse(response).getBodyOffset(),
                response.length
        ));
    }

    public static String getRequestBodyString(IHttpRequestResponse requestResponse) {
        return helpers.bytesToString(getRequestBody(requestResponse));
    }
    public static byte[] getRequestBody(IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = Utilities.helpers.analyzeRequest(
                requestResponse.getHttpService(),
                requestResponse.getRequest()
        );
        byte[] request = requestResponse.getRequest();
        return Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
    }

    public static String getResponseBodyString(IHttpRequestResponse requestResponse) {
        return helpers.bytesToString(getResponseBody(requestResponse));
    }
    public static byte[] getResponseBody(IHttpRequestResponse requestResponse) {
        IResponseInfo responseInfo = Utilities.helpers.analyzeResponse(requestResponse.getResponse());
        byte[] response = requestResponse.getResponse();
        return Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
    }

    public static String[] splitHeader(String header) {
        if (!header.contains(":")) {
            return new String[]{header, null};
        }
        String name = header.substring(0, header.indexOf(":")).trim();
        String value = header.substring(header.indexOf(":")+1).trim();
        return new String[]{name, value};
    }

    public static void enableDebug() {
        debug = true;
    }

    public static void disableDebug() {
        debug = false;
    }

    public static boolean isDebug() {
        return debug;
    }

    public static String generateRandomString(int length) {
        int leftLimit = 65; // letter 'A'
        int rightLimit = 90; // letter 'Z'
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(length)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }
}
