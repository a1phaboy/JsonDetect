package burp;

import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.HttpAnalyze;
import burp.Bootstrap.YamlReader;
import burp.Scan.JsonScan;
import burp.View.Tags;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

public class BurpExtender implements IBurpExtender,IHttpListener,IScannerCheck{
    public static String NAME = "a1Scan";

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static YamlReader yamlReader;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private Tags tags;



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        //设置名称
        callbacks.setExtensionName(NAME);

        //输入输出
        stdout = new PrintWriter(callbacks.getStdout(),true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        //初始化
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        BurpExtender.yamlReader = YamlReader.getInstance(callbacks);

        //UI界面
        this.tags = new Tags(callbacks,NAME);



        //注册
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);

    }

    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        stdout.println((b? "HTTP request to " : "HTTP response from ") +
                iHttpRequestResponse.getHttpService() + "[" + callbacks.getToolName(i) + "]");
        iHttpRequestResponse.setHighlight("yellow");
        iHttpRequestResponse.setComment("Json");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        stdout.println("===== doPassiveScan =====");
        List<String> domainNameBlacklist = yamlReader.getStringList("scan.domainName.blacklist");

        //获取url
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(callbacks,baseRequestResponse);

        //请求分析
        HttpAnalyze httpAnalyze = new HttpAnalyze(callbacks,baseRequestResponse) ;
        if (httpAnalyze.AnalyzeJsonByReqBody()){   // 判断body是否是json格式数据
            int tagId = this.tags.getScanQueueTagClass().add(
                    "json",
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    "waiting for test results",
                    baseRequestResponse
            );
            JsonScan scan = null;
            try {
                scan = new JsonScan(callbacks,baseRequestResponse,yamlReader);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            assert scan != null;
            this.tags.getScanQueueTagClass().save(
                    tagId,
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    "json",
                    scan.getResult(),
                    baseRequestResponse
            );
            stdout.println(scan.getResult());
//            HashMap<String,byte[]> payloadMap = scan.getPayloadMap();
//            for (String type : payloadMap.keySet()) {
//                stdout.println("Type:" + type );
//                stdout.println("payload:"+ new String(payloadMap.get(type)));
//                stdout.println("==================================");
//            }



            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) },
                    "Json",
                    "The response contains the string: " + "json",
                    "Information"));
            return issues;
        }
       return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
