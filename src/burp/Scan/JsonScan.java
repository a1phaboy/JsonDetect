package burp.Scan;

import burp.*;
import burp.Bootstrap.YamlReader;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class JsonScan implements ScanTask{
    private static IBurpExtenderCallbacks callbacks;
    private static IHttpRequestResponse requestResponse;
    private static YamlReader yamlReader;
    private static IBurpCollaboratorClientContext burpCollaboratorClient;
    private static IExtensionHelpers helpers;
    private static String dnsurl;
    private static String result;
    private HashMap<String,byte[]> fastjsonPayloadMap;
    private HashMap<String,byte[]> orgjsonPayloadMap;


    public JsonScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, YamlReader yamlReader) throws InterruptedException {
        JsonScan.callbacks = callbacks;
        JsonScan.requestResponse = requestResponse;
        JsonScan.yamlReader = yamlReader;
        JsonScan.burpCollaboratorClient = callbacks.createBurpCollaboratorClientContext();
        JsonScan.helpers = callbacks.getHelpers();
        fastjsonPayloadMap = new HashMap<>();
        orgjsonPayloadMap = new HashMap<>();
        JsonScan.dnsurl = this.initPayloadMap();
        JsonScan.result = "";
        this.doScan();
    }

    //初始化payloadMap
    private String initPayloadMap(){
        //获取DNS payload
        String dnsurl = burpCollaboratorClient.generatePayload(true);

        /*
         * fastjson detect
         */
        byte[] errDetect = yamlReader.getString("application.fastjson.payloads.errDetect").getBytes();
        byte[] netDetect = String.format(yamlReader.getString("application.fastjson.payloads.netDetect"),dnsurl).getBytes();
        byte[] autoTypeDetect = String.format(yamlReader.getString("application.fastjson.payloads.autoTypeDetect"),dnsurl).getBytes();
        byte[] dnsDetect48 = String.format(yamlReader.getString("application.fastjson.payloads.dnsDetect48"),dnsurl).getBytes();
        byte[] dnsDetect68 = String.format(yamlReader.getString("application.fastjson.payloads.dnsDetect68"),dnsurl).getBytes();
        byte[] desDetect80 = String.format(yamlReader.getString("application.fastjson.payloads.desDetect80"),dnsurl,dnsurl).getBytes();

        fastjsonPayloadMap.put("errDetect",Arrays.copyOfRange(errDetect,1,errDetect.length-1));
        fastjsonPayloadMap.put("netDetect",Arrays.copyOfRange(netDetect,1,netDetect.length-1));
        fastjsonPayloadMap.put("autoTypeDetect",Arrays.copyOfRange(autoTypeDetect,1,autoTypeDetect.length-1));
        fastjsonPayloadMap.put("dnsDetect48",Arrays.copyOfRange(dnsDetect48,1,dnsDetect48.length-1));
        fastjsonPayloadMap.put("dnsDetect68",Arrays.copyOfRange(dnsDetect68,1,dnsDetect68.length-1));
        fastjsonPayloadMap.put("dnsDetect80",Arrays.copyOfRange(desDetect80,1,desDetect80.length-1));

        /*
         * org.fastjson detect
         */
        byte[] orgjsonDetect = String.format(yamlReader.getString("application.orgjson.payloads.errDetect"),dnsurl,dnsurl).getBytes();
        orgjsonPayloadMap.put("errDetect",Arrays.copyOfRange(orgjsonDetect,1,orgjsonDetect.length-1));


        return dnsurl;
    }


    @Override
    public void doScan() throws InterruptedException {
        //报错探测
        byte[] errDetectReq = rebuildReq(requestResponse,fastjsonPayloadMap.get("errDetect"));
        IHttpRequestResponse doReq = callbacks.makeHttpRequest(requestResponse.getHttpService(), errDetectReq);
        String errResp =  new String(doReq.getResponse());
        int pos = errResp.indexOf("fastjson-version");
        if( pos != -1){
            result =  "[*]" + new String(Arrays.copyOfRange(doReq.getResponse(),pos,pos+23)) + " ｜ ";
        }

        //DNS探测
        //先进行出网检测
        boolean netout = false;
        sendDnsPayload("netDetect");
        for(IBurpCollaboratorInteraction dnslog : burpCollaboratorClient.fetchCollaboratorInteractionsFor(getDnsurl())){
            String de_dnslog = new String(Base64.getDecoder().decode(dnslog.getProperty("raw_query")), StandardCharsets.UTF_8);
            if(de_dnslog.contains("NETOUT_")){
                //有记录
                netout = true;
                break;
            }
        }
        if(netout){
            //autoType状态检测
            boolean autoType = false;
            sendDnsPayload("autoTypeDetect");
            for(IBurpCollaboratorInteraction dnslog : burpCollaboratorClient.fetchCollaboratorInteractionsFor(getDnsurl())){
                String de_dnslog = new String(Base64.getDecoder().decode(dnslog.getProperty("raw_query")), StandardCharsets.UTF_8);
                if(de_dnslog.contains("AUTOTYPE_")){
                    //有记录
                    autoType = true;
                    break;
                }
            }
            //报错探测拿到的版本,不需要做进一步的探测了
            if(!result.isEmpty()){
                result = result + (autoType?" autoType On":" autoType Off");
                return ;
            }
            //判断fastjson版本
            String errresult;
            errresult = sendDnsPayload("dnsDetect48");
            if(!errresult.equals("")){
                result = errresult + (autoType?" autoType On":" autoType Off");
                return ;
            }
            errresult = sendDnsPayload("dnsDetect68");
            if(!errresult.equals("")){
                result = errresult + (autoType?" autoType On":" autoType Off");
                return ;
            }
            errresult = sendDnsPayload("dnsDetect80");
            if(!errresult.equals("")){
                result = errresult + (autoType?" autoType On":" autoType Off");
                return ;
            }
            for(IBurpCollaboratorInteraction dnslog : burpCollaboratorClient.fetchCollaboratorInteractionsFor(getDnsurl())){
                String de_dnslog = new String(Base64.getDecoder().decode(dnslog.getProperty("raw_query")), StandardCharsets.UTF_8);
                if(de_dnslog.contains("48_")){
                    //有记录
                    result = "[*]Fastjson < 1.2.48 | " + (autoType?"autoType On":"autoType Off");
                    break;
                }
                if(de_dnslog.contains("68_")){
                    if(autoType){
                        result = "[*]Fastjson ≥ 1.2.48 | autoType On";
                    }else{
                        result = "[*]1.2.48 ≤ Fastjson ≤ 1.2.68 | autoType Off";
                    }
                    break;
                }
                if(de_dnslog.contains("83_")){
                    result = "[*]Fastjson ==1.2.83 | autoType Off";
                    break;
                }
                if(de_dnslog.contains("80_")){
                    result = "[*]1.2.69 ≤ Fastjson ≤ 1.2.80 | autoType Off";
                    break;
                }
            }
        }
        else {
            if(result.isEmpty()){
                /*
                 * 这里可以判断各类的json依赖库
                 * ===== 施工中 =====
                 */
                errDetectReq = rebuildReq(requestResponse,orgjsonPayloadMap.get("errDetect"));
                doReq = callbacks.makeHttpRequest(requestResponse.getHttpService(), errDetectReq);
                errResp =  new String(doReq.getResponse());
                pos = errResp.indexOf("org.json");
                if( pos != -1){
                    result =  "[+] org.json ";
                }

                pos = errResp.indexOf("jackson");
                if( pos != -1){
                    result =  "[+] jackson";
                    return ;
                }
                result = "[-]未检测出json库";

            }
            else{
                result += "不出网";
            }
        }
    }

    @Override
    public String getResult() {
        return result;
    }

    public byte[] rebuildReq(IHttpRequestResponse request,byte[] payload){
        IRequestInfo req = helpers.analyzeRequest(request);
        List<String> req_head = req.getHeaders();
        return helpers.buildHttpMessage(req_head,payload);
    }
    public String getDnsurl(){
        return dnsurl;
    }

    public HashMap<String,byte[]> getPayloadMap(){
        return this.fastjsonPayloadMap;
    }
    public String sendDnsPayload(String type) throws InterruptedException {
        byte[] Detect = rebuildReq(requestResponse,fastjsonPayloadMap.get(type));
        IHttpRequestResponse doReq = callbacks.makeHttpRequest(requestResponse.getHttpService(), Detect);
        String errResp =  new String(doReq.getResponse());
        int pos = errResp.indexOf("fastjson-version");
        if( pos != -1){
            result =  "[*]" + new String(Arrays.copyOfRange(doReq.getResponse(),pos,pos+23)) + " ｜ ";
            return result;
        }else{
            Thread.sleep(5000);
            return "";
        }


    }
}
