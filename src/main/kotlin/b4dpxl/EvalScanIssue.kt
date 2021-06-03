package b4dpxl

import burp.IHttpRequestResponse
import burp.IHttpService
import burp.IRequestInfo
import burp.IScanIssue
import java.net.URL

class EvalScanIssue(requestResponse: IHttpRequestResponse, url: String, detail: String, severity: String = "Medium", confidence: String = "Firm") : IScanIssue {

    val _url: URL
    val _detail = detail.trim()
    val _severity = severity
    val _confidence = confidence
    val _requestResponse = requestResponse

    init {
        // insert the port into the URL if missing
        var u = URL(url)
        if (u.port < 0) {
            val requestInfo = Utilities.helpers.analyzeRequest(requestResponse.httpService, requestResponse.request)
            u = URL(u.protocol, u.host, requestInfo.url.port, u.path);
        }
        _url = u
    }

    override fun getUrl(): URL {
        return _url
    }

    override fun getIssueName(): String {
        return "JavaScript eval() call"
    }

    override fun getIssueType(): Int {
        return 0
    }

    override fun getSeverity(): String {
        return _severity
    }

    override fun getConfidence(): String {
        return _confidence
    }

    override fun getIssueBackground(): String? {
        return """<code>eval()</code> is a dangerous JavaScript function, which executes arbitrary code in the context of the caller. If an attacker can influence the code which is called, they can run custom scripts and exploit vulnerabilities such as Cross-Site Scripting (XSS). Alternative, safe methods can usually be found which do not rely on the eval() and related Function() methods."""
    }

    override fun getRemediationBackground(): String? {
        return null
    }

    override fun getIssueDetail(): String {
        return _detail
    }

    override fun getRemediationDetail(): String? {
        return null
    }

    override fun getHttpMessages(): Array<IHttpRequestResponse> {
        return emptyArray()
//        return arrayOf(_requestResponse)
    }

    override fun getHttpService(): IHttpService {
        return _requestResponse.httpService
    }
}