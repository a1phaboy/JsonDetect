package burp;

import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.HttpAnalyze;
import burp.Bootstrap.YamlReader;
import burp.Scan.JsonScan;
import burp.View.Tags;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class BurpExtender implements IBurpExtender,IHttpListener,IScannerCheck{
    public static String NAME = "JsonDetect";

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

        //banner
        showSomething();


        //注册
        callbacks.registerHttpListener(this);
        callbacks.registerScannerCheck(this);

    }

    @Override
    public void processHttpMessage(int i, boolean isRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isRequest){
            HttpAnalyze httpAnalyze = new HttpAnalyze(callbacks,iHttpRequestResponse) ;
            if (httpAnalyze.AnalyzeJsonByReqBody()){
                iHttpRequestResponse.setHighlight("yellow");
                iHttpRequestResponse.setComment("JsonType");
            }
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        stdout.println("===== doPassiveScan =====");
        List<String> domainNameBlacklist = yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = yamlReader.getStringList("scan.domainName.whitelist");

        //获取url
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(callbacks,baseRequestResponse);


        //判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return null;
            }
        }

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }


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


    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     * 是 = true, 否 = false
     *
     * @param burpUrl
     * @return
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    public void showSomething(){
        stdout.println("==========================");
        stdout.println("v1.0 powered by a1phaboy");
        stdout.println("Github:https://github.com/a1phaboy");
        stdout.println("wx:aWFtYTFwaGFib3k=");
        stdout.println("==========================");
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
