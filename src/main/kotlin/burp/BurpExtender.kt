package burp

import b4dpxl.Evaluator

class BurpExtender : IBurpExtender {

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?) {
        Evaluator(callbacks)
    }

}