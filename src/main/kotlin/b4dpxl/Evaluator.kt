package b4dpxl

import burp.*
import com.beust.klaxon.Klaxon
import java.awt.Frame
import javax.swing.JCheckBoxMenuItem
import javax.swing.JFrame
import javax.swing.JMenu
import javax.swing.JMenuItem

class Evaluator constructor(callbacks: IBurpExtenderCallbacks?) : IProxyListener, IExtensionStateListener {

    private val extensionName = "Evaluator"
    private var evalNamePrefix: String

    private val menu: JMenu
    private val enabledMenu: JCheckBoxMenuItem
    private val callbackMenu: JCheckBoxMenuItem

    private val configPrefixName = "evalNamePrefix"
    private val configEnabled = "enabled"
    private val configCallback = "callback"

    init {
        Utilities(callbacks, true)
        Utilities.callbacks.setExtensionName(extensionName)
        Utilities.callbacks.registerProxyListener(this)
        Utilities.callbacks.registerExtensionStateListener(this)

        val savedPrefix: String? = Utilities.callbacks.loadExtensionSetting(configPrefixName)
        evalNamePrefix = savedPrefix ?: Utilities.generateRandomString(8)
        Utilities.callbacks.saveExtensionSetting(configPrefixName, evalNamePrefix)
        Utilities.println("Using prefix ${evalNamePrefix}")

        menu = JMenu(extensionName)
        enabledMenu = JCheckBoxMenuItem("Enabled", (Utilities.callbacks.loadExtensionSetting(configEnabled) ?: "false").toBoolean())
        menu.add(enabledMenu)
        callbackMenu = JCheckBoxMenuItem("Use callback", (Utilities.callbacks.loadExtensionSetting(configCallback) ?: "false").toBoolean())
        menu.add(callbackMenu)
        val prefixMenu = JMenuItem("Reset prefix")
        prefixMenu.addActionListener {
            evalNamePrefix = Utilities.generateRandomString(8)
            Utilities.callbacks.saveExtensionSetting(configPrefixName, evalNamePrefix)
            Utilities.println("Using prefix ${evalNamePrefix}")
        }
        menu.add(prefixMenu)

        for (frame in Frame.getFrames()) {
            if (frame.isVisible && frame.title.startsWith("Burp Suite") && frame is JFrame) {
                val menuBar = (frame as JFrame).jMenuBar
                menuBar.add(menu)
                Utilities.println("Added menu")
                break
            }
        }
        Utilities.println("Loaded ${extensionName}!")
    }

    override fun processProxyMessage(messageIsRequest: Boolean, proxyMessage: IInterceptedProxyMessage) {

        if (! enabledMenu.isSelected) {
            return;
        }

        val requestResponse = proxyMessage.messageInfo
        val requestInfo = Utilities.helpers.analyzeRequest(requestResponse?.httpService, requestResponse?.request)

        if (! Utilities.callbacks.isInScope(requestInfo.url)) {
            return
        }

        if (messageIsRequest){
            if (!callbackMenu.isSelected) {
                return
            }

            val headers = requestInfo.headers.filter{it.contains(":")}.associate {
                it.split(":").let{ (header, value) -> header to value.trim()}
            }
            if (requestInfo.method == "PUT" && headers.contains("X-EVALUATOR") && requestInfo.contentType == IRequestInfo.CONTENT_TYPE_JSON) {
                Utilities.debug("Got Evaluator callback")
                val json = Klaxon().parse<Map<String, String>>(Utilities.getRequestBodyString(requestResponse))!!
                try {

                    val baseURL = json.getValue("url").split("?")[0]  // strip the querystring from the URL // TODO: find a better way to do this
                    val issue = EvalScanIssue(
                        requestResponse,
                        baseURL,
                        """<p>The page called the JavaScript <code>eval()</code> function from <code>${requestInfo.url}</code></p>
<p>
<b>Executed call:</b> <code>${json.getValue("call")}</code>
</p>
<p>
<b>Requesting URL:</b> <code>${json.getValue("url")}</code>
</p>
<b>Source:</b>
</p>
<pre><code>
${json.getValue("script")}
</code></pre>
<br />
<p>Note: The <code>eval()</code> call was renamed to <code>${evalNamePrefix}_eval()</code> by ${extensionName}.</p>
""".trim()
                    )

                    var isNewIssue = true
                    // when using getScanIssues we don't want the port (if it's standard)
                    for (existingIssue in Utilities.callbacks.getScanIssues(baseURL)) {
                        if (
                            existingIssue.url == issue.url &&
                            existingIssue.issueName == issue.issueName
                        ) {
//                            if (existingIssue.issueDetail?.replace(nonPrintable, "") == issue.issueDetail.replace(nonPrintable, "")) {
                            // does the issue contain the JS url, code, and call?
                            val truncatedExistingIssueDetail = stripChars(existingIssue.issueDetail)
                            if (
                                truncatedExistingIssueDetail.contains(stripChars(requestInfo.url.toString())) &&
                                truncatedExistingIssueDetail.contains(stripChars(json.getValue("call"))) &&
                                truncatedExistingIssueDetail.contains(stripChars(json.getValue("script")))
                            ) {
                                isNewIssue = false
                                break
                            }
                        }

                    }

                    Utilities.println("new issue? ${isNewIssue}")

                    if (isNewIssue) {
                        Utilities.callbacks.addScanIssue(issue)
                        Utilities.debug("issue created")
                    }
                } catch (e: Exception) {
                    Utilities.err(e.message)
                }
                proxyMessage.interceptAction = IInterceptedProxyMessage.ACTION_DROP
                requestResponse.comment = "Update from Evaluator"
                requestResponse.highlight = "gray"
            }


        } else {

            val responseInfo = Utilities.helpers.analyzeResponse(requestResponse?.response)
            val body: String = Utilities.helpers.bytesToString(Utilities.getResponseBody(requestResponse))

            val rex = "\\b(eval\\s*\\()"
            val pattern = Regex(rex)

            if (responseInfo.inferredMimeType.equals("script", true) && pattern.containsMatchIn(body)) {
                val url = requestInfo.url
                Utilities.println("Found ${pattern.findAll(body).count()} eval() to modify in ${url}")

                var newBody = """
function ${evalNamePrefix}_eval(x) {
    call = `eval(${"$"}{x})`;
    code = "";
    msg = call;
    if (${evalNamePrefix}_eval.caller != null) {
        msg += "\n> " + String(${evalNamePrefix}_eval.caller).match(/(?<=${evalNamePrefix}_)eval\(.*?\)/)[0];
    }
    console.info(`In ${"$"}{location.href}:\n${"$"}{msg}`);
    if (${evalNamePrefix}_eval.caller != null) {
        code = String(${evalNamePrefix}_eval.caller).replace("${evalNamePrefix}_eval(", "eval(");
        console.debug("${evalNamePrefix}_eval() called by: " + code);
    }
"""
                if (callbackMenu.isSelected) {
                    newBody += """                    
    // send the request back to burp for logging
    try {
        data = {
            "url": location.href,
            "call": call,
            "script": code
        };
        fetch('${url}', {
            method: 'PUT',
            body: JSON.stringify(data),
            headers: {"Content-Type": "application/json", "X-EVALUATOR": "1"}
        });
    } catch (e) {console.error(e);}
    """
                }

                newBody += """
    return eval(x);
}
""" + body.replace(pattern, evalNamePrefix + "_eval(")

                requestResponse?.response = Utilities.helpers.buildHttpMessage(
                    responseInfo.headers,
                    Utilities.helpers.stringToBytes(newBody)
                )
            }
        }
    }

    override fun extensionUnloaded() {
        Utilities.debug("Unloading ${extensionName}")
        Utilities.callbacks.saveExtensionSetting(configEnabled, enabledMenu.isSelected.toString())
        Utilities.callbacks.saveExtensionSetting(configCallback, callbackMenu.isSelected.toString())
        menu.parent.remove(menu)
        menu.parent.repaint()
    }

    private val nonPrintable = Regex("[^\\x21-\\x7E]")  // having to strip these for the comparison for some reason

    private fun stripChars(input: String) : String {
        return input.replace(nonPrintable, "")
    }


}