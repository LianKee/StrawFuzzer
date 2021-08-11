package config;

import database.SqliteDb;

import java.io.File;

public class Common {

    public static String systemDir = System.getProperty("user.dir");
    public static String projectPath=systemDir.replace(File.separator+"StaticAnalyzer","");
    // for test
    public static String SimpleTestDir = projectPath+File.separator+"Results"+File.separator+"SimpleTest";
    public static String TestOutputDir = projectPath+File.separator+"Results"+File.separator+"Output";
    public static String TestApkDir = projectPath+File.separator+"Results"+File.separator+"TestApk";

    public static String DeviceInfo = null;
    public static String resultDirPath;
    private static String databasePath;
    public static SqliteDb database;
    public static int ThreadSize=32;

    public static String SourceDir;
    public static String ServiceInterfacePath;
    public static String ServiceListPath;
    public static String InputJavaDir;
    public static String OutputJimpleDir;
    public static String InputJimpleDir;
    public static String CustomizedAndroidJarPath;
    public static String javaSourceDir;

    public static String[] illegalSignature = new String[]{
    };
    public static String[] validSignature = new String[]{
            "<android.*", "<com.android.*", "<pkg.*", "<pkgmain.*", "<main.*", "<org.*"};

    public static String[] validClassName = new String[]{
            "android.*","com.android.*","org.*"
    };

    public static String all_type = "All";
    public static String linkToDeath_type = "LinkToDeath";
    public static String rootSet_type = "RootSet";
    public static String oneShot_type = "OneShot";

    public static boolean concernInvokeBetweenInterfaces = true;

    public static void init(String deviceInfo){
        DeviceInfo = deviceInfo;
        resultDirPath = projectPath+ File.separator+"Android_Framework_Source" +File.separator+"StaticAnalysisResults"+File.separator+DeviceInfo;
        File dir = new File(resultDirPath);
        if (!dir.exists()){
            if(!dir.mkdir())
                System.out.println("Make output dir failed");
        }
        databasePath = "databases/SourceReader_"+DeviceInfo+".db";
        database = null;

        if (deviceInfo.contains("Android11"))
            javaSourceDir = projectPath + File.separator + "Android_Framework_Source" + File.separator + "android-30";
        else
            javaSourceDir = projectPath + File.separator + "Android_Framework_Source" + File.separator + "android-29";

        SourceDir = projectPath+ File.separator+"Android_Framework_Source" +File.separator+"Inputs"+File.separator+DeviceInfo;

        ServiceInterfacePath = SourceDir+File.separator+DeviceInfo+"_AllServices.txt";
        ServiceListPath = SourceDir+File.separator+"ServiceList.txt";
        InputJavaDir = SourceDir+File.separator+"Source";
        OutputJimpleDir = SourceDir+File.separator+"Jimple";
        InputJimpleDir = OutputJimpleDir;
        CustomizedAndroidJarPath = SourceDir+File.separator+DeviceInfo+".jar";
    }




}
