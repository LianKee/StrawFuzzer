package serviceInterfaces;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;

import static serviceInterfaces.ServiceInterfaces.replaceArrayFormatFromJavaToSoot;

public class SystemServiceInfo {
    public String serviceInterfacePath;
    public HashMap<String, String> serviceNameMapStubClass = new HashMap<>();
    public HashMap<String, String> stubClassMapServiceName = new HashMap<>();
    public HashMap<String, HashSet<String>> stubClassNameMapRawInterfaces = new HashMap<>();

    public SystemServiceInfo(String serviceInterfacePath){
        this.serviceInterfacePath = serviceInterfacePath;
        try{
            BufferedReader in = new BufferedReader(new FileReader(serviceInterfacePath));
            String str;
            String serviceName = "";
            String stubClassName = "";
            while ((str = in.readLine()) != null) {
                if (str.startsWith("Name:"))
                    serviceName = str.split(":")[1].trim();
                else if (str.startsWith("StubClassName:")) {
                    stubClassName = str.split(":")[1].trim() + "$Stub";
                    // public interfaces
                    if (!stubClassName.equals("null$Stub")) {
                        serviceNameMapStubClass.put(serviceName, stubClassName);
                        stubClassMapServiceName.put(stubClassName, serviceName);
                        stubClassNameMapRawInterfaces.put(stubClassName,new HashSet<>());
                    }
                } else if (str.trim().startsWith("<")) {
                    str = replaceArrayFormatFromJavaToSoot(str.trim());
                    if (str.endsWith("android.os.IBinder asBinder()>") || str.endsWith("java.lang.String getInterfaceDescriptor()>"))
                        continue;
                    stubClassNameMapRawInterfaces.get(stubClassName).add(str);
                }
            }
            in.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
