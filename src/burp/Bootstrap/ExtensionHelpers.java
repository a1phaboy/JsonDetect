package burp.Bootstrap;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.View.Tags;

import java.io.File;

public class ExtensionHelpers {

    private static IExtensionHelpers helpers;
    private static IBurpExtenderCallbacks callbacks;
    private Tags tags;

    public ExtensionHelpers(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

    }




    public String getExtensionFilePath() {
        String path = "";
        Integer lastIndex = this.callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = this.callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

}
