package burp.Scan;

public interface ScanTask {

    void doScan() throws InterruptedException;

    String getResult();

}
