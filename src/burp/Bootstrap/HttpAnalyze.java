package burp.Bootstrap;

import burp.*;

import java.util.Arrays;

public class HttpAnalyze {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static IHttpRequestResponse requestResponse;

    public HttpAnalyze(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse){
        HttpAnalyze.callbacks = callbacks;
        HttpAnalyze.helpers = callbacks.getHelpers();
        HttpAnalyze.requestResponse = baseRequestResponse;
    }

    public IRequestInfo AnalyzeRequest() {
        return helpers.analyzeRequest(requestResponse.getRequest());
    }

    public IResponseInfo AnlyzeResponse(){
        return helpers.analyzeResponse(requestResponse.getResponse());
    }

    /* json分析
     * 需要判断 请求包中的body数据是否是json字符串
     * 如果是 ，则判断为json；否 则返回 false
     */
    public boolean AnalyzeJsonByReqBody(){
        int ReqBodyOffset = this.AnalyzeRequest().getBodyOffset();
        byte[] byteReqBody = Arrays.copyOfRange(requestResponse.getRequest(),ReqBodyOffset,requestResponse.getRequest().length);
        String ReqBody = new String(byteReqBody).trim();
        if(ReqBody.startsWith("{") && ReqBody.endsWith("}")){
            return true;
        }
        return ReqBody.startsWith("[") && ReqBody.endsWith("]");
    }
}