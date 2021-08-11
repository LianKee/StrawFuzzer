package util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class LogUtil {

    public static void log(String msg){
        System.out.println(msg);
    }

    public static void error(String tag,String msg){
        System.out.println(tag+" : "+TimeMeasurement.currentTime()+"\n");
        System.out.println(msg+"\n\n");
        File logFile=new File("error.txt");
        try {
            if(!logFile.exists())
                logFile.createNewFile();
            BufferedWriter writer=new BufferedWriter(new FileWriter(logFile,true));
            writer.write(tag+" : "+TimeMeasurement.currentTime()+"\n");
            System.out.println(tag+" : "+TimeMeasurement.currentTime()+"\n");
            writer.write(msg+"\n\n");
            System.out.println(msg+"\n\n");
            writer.flush();
            writer.close();
        } catch (Exception e) {
            error("File Error1 : "+tag, msg);
        }
    }

    public static  synchronized void exception(String tag,String msg,Exception e){
        log(tag+" EXCEPTION : "+msg);
        File logFile=new java.io.File("exception.txt");
        try {
            if(!logFile.exists())
                logFile.createNewFile();
            BufferedWriter writer=new BufferedWriter(new FileWriter(logFile,true));
            writer.write(tag+" : "+TimeMeasurement.currentTime()+"\n");
            writer.write(msg+"\n");
            for(StackTraceElement element : e.getStackTrace())
                writer.write(element+"\n");
            writer.write("\n");
            writer.flush();
            writer.close();
        } catch (Exception e2) {
            error("File Error4 : "+tag, msg);
        }
    }

    public static void debug(String tag,String msg){
        log(tag+" DEBUG : "+msg);
    }

}
