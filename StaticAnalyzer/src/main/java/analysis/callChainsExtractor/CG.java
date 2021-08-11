package analysis.callChainsExtractor;

import serviceInterfaces.ServiceInterfaces;
import soot.*;
import soot.jimple.*;
import util.StringUtil;
import util.TimeMeasurement;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import static main.Memory.*;

public class CG {

    private static String[] messagePrecessMethodNames = new String[]{
            "sendMessage","sendMessageDelayed","sendMessageAtTime","sendMessageAtFrontOfQueue","sendEmptyMessageAtTime",
            "post","postDelayed","postAtTime","postAtFrontOfQueue","sendEmptyMessage"
    };
    private static HashSet<String> messagePrecessMethodNameSet = new HashSet<>(Arrays.asList(messagePrecessMethodNames));

    private static String[] abandonMethodSigs = new String[]{
            "<android.os.BaseBundle: void readFromParcelInner(android.os.Parcel,int)>"
    };
    private static HashSet<String> abandonMethodSet = new HashSet<String>(Arrays.asList(abandonMethodSigs));

    public static void buildCallGraph() {
        TimeMeasurement.show("Build Call Graph Begin");

        mapStubInterface();
        mapMessageHandler();
        mapVirtualMethod();
        mapCreateFromParcel();

        TimeMeasurement.show("Build Call Graph End");
    }


    private static void mapStubInterface(){
        for (String methodSig: ServiceInterfaces.allRawInterfaceSigs){
            HashSet<String> callees = ServiceInterfaces.allRawInterfaceSigMapMethodsInDeserialization.get(methodSig);
            callerMethodSignatureMapCalleeMethodSignatures.put(methodSig, callees);
            for (String calleeSig:callees){
                if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(calleeSig)){
                    calleeMethodSignatureMapCallerMethodSignatures.put(calleeSig,new HashSet<>());
                }
                calleeMethodSignatureMapCallerMethodSignatures.get(calleeSig).add(methodSig);
            }
        }
    }

    private static void mapMessageHandler(){
        for (String callerSig : callerMethodSignatureMapCalleeMethodSignatures.keySet()) {
            HashSet<String> calleeSigs = new HashSet<>(callerMethodSignatureMapCalleeMethodSignatures.get(callerSig));
            for (String calleeSig:callerMethodSignatureMapCalleeMethodSignatures.get(callerSig)){
                String calleeMethodName = StringUtil.getMethodNameFromMethodSig(calleeSig);
                if (messagePrecessMethodNameSet.contains(calleeMethodName)){
                    SootClass targetClass = classNameMapSootClass.get(StringUtil.getDeclareClassFromMethodSig(calleeSig));
                    if (targetClass == null)
                        continue;

                    if (isHandler(targetClass)){
                        try{
                            SootMethod handleMessageMethod = targetClass.getMethodByNameUnsafe("handleMessage");
                            if (handleMessageMethod != null){
                                String handleMessageSig = handleMessageMethod.getSignature();
                                calleeSigs.add(handleMessageSig);
                                if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(handleMessageSig))
                                    calleeMethodSignatureMapCallerMethodSignatures.put(handleMessageSig,new HashSet<>());
                                calleeMethodSignatureMapCallerMethodSignatures.get(handleMessageSig).add(callerSig);
                            }
                        }catch (Exception e){
                        }
                    }
                }
            }
            callerMethodSignatureMapCalleeMethodSignatures.put(callerSig,calleeSigs);
        }
    }

    private static void mapVirtualMethod(){
        for (String callerSig : callerMethodSignatureMapCalleeMethodSignatures.keySet()) {
            HashSet<String> optimizedCallees = new HashSet<>();
            String sig;
            if (!abandonMethodSet.contains(callerSig)){
                for (String calleeSig : callerMethodSignatureMapCalleeMethodSignatures.get(callerSig)) {
                    // abandon some methods
                    if (abandonMethodSet.contains(calleeSig))
                        continue;

                    sig = mapIPCCalleeMethod(calleeSig);
                    if (sig==null || !methodSignatureMapSootMethod.containsKey(sig))
                        continue;
                    SootMethod calleeMethod = methodSignatureMapSootMethod.get(sig);
                    if (calleeMethod.isConcrete()){
                        if (isBaseClassMethod(calleeMethod)){
                            HashSet<String> implMethodSigs = getImplMethodSigsFromSonClasses(calleeMethod);
                            optimizedCallees.addAll(implMethodSigs);
                            for (String implSig:implMethodSigs){
                                if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(implSig))
                                    calleeMethodSignatureMapCallerMethodSignatures.put(implSig, new HashSet<>());
                                calleeMethodSignatureMapCallerMethodSignatures.get(implSig).add(callerSig);
                            }
                        } else {
                            optimizedCallees.add(sig);
                            if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(sig))
                                calleeMethodSignatureMapCallerMethodSignatures.put(sig, new HashSet<>());
                            calleeMethodSignatureMapCallerMethodSignatures.get(sig).add(callerSig);
                        }
                    }else {
                        if (calleeMethod.isAbstract()){
                            optimizedCallees.add(sig);
                            HashSet<String> implMethodSigs = getImplMethodSigsFromSonClasses(calleeMethod);
                            optimizedCallees.addAll(implMethodSigs);
                            for (String implSig:implMethodSigs){
                                if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(implSig))
                                    calleeMethodSignatureMapCallerMethodSignatures.put(implSig, new HashSet<>());
                                calleeMethodSignatureMapCallerMethodSignatures.get(implSig).add(callerSig);
                            }
                        }
                    }
                }
                callerMethodSignatureMapCalleeMethodSignatures.put(callerSig, optimizedCallees);
            }

            callerMethodSignatureMapCalleeMethodSignatures.put(callerSig, optimizedCallees);
        }
    }

    private static void mapCreateFromParcel(){
        for (String callerSig: callerMethodSignatureMapCalleeMethodSignatures.keySet()){
            if (callerMethodSignatureMapCalleeMethodSignatures.get(callerSig).contains("<android.os.Parcelable$Creator: java.lang.Object createFromParcel(android.os.Parcel)>")){
                SootMethod sootMethod = methodSignatureMapSootMethod.get(callerSig);
                if (sootMethod != null && sootMethod.isConcrete()){
                    Body body = sootMethod.retrieveActiveBody();
                    HashMap<String,String> localMapClass = new HashMap<>();
                    for (Unit unit:body.getUnits()){
                        if (unit instanceof AssignStmt && ((AssignStmt) unit).containsFieldRef()){
                            if (((AssignStmt) unit).getFieldRef().getField().getSignature().contains(" android.os.Parcelable$Creator ")){
                                localMapClass.put(((AssignStmt) unit).getLeftOp().toString(),((AssignStmt) unit).getFieldRef().getField().getDeclaringClass().getName());
                            }
                        }
                        if (((Stmt)unit).containsInvokeExpr()){
                            InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                            if (invokeExpr.getMethodRef().getSignature().equals("<android.os.Parcelable$Creator: java.lang.Object createFromParcel(android.os.Parcel)>")){
                                String callerLocalName = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue().toString();
                                if (localMapClass.containsKey(callerLocalName)){
                                    String declaringClassName = localMapClass.get(callerLocalName);
                                    String newCalleeSig = "<"+declaringClassName+": void <init>(android.os.Parcel)>";
                                    boolean flag = false;
                                    if (methodSignatureMapSootMethod.containsKey(newCalleeSig)){
                                        callerMethodSignatureMapCalleeMethodSignatures.get(callerSig).add(newCalleeSig);
                                        flag=true;
                                    }else{
                                        for (int i=1;i<=36;++i){
                                            newCalleeSig = "<"+declaringClassName+"$"+i+": "+declaringClassName+" createFromParcel(android.os.Parcel)>";
                                            if (methodSignatureMapSootMethod.containsKey(newCalleeSig)){
                                                callerMethodSignatureMapCalleeMethodSignatures.get(callerSig).add(newCalleeSig);
                                                flag = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (flag){
                                        callerMethodSignatureMapCalleeMethodSignatures.get(callerSig).remove("<android.os.Parcelable$Creator: java.lang.Object createFromParcel(android.os.Parcel)>");

                                        if (!calleeMethodSignatureMapCallerMethodSignatures.containsKey(newCalleeSig))
                                            calleeMethodSignatureMapCallerMethodSignatures.put(newCalleeSig,new HashSet<>());
                                        calleeMethodSignatureMapCallerMethodSignatures.get(newCalleeSig).add(callerSig);
                                        // record
                                        if (!CGMethodMap.containsKey(body)){
                                            CGMethodMap.put(body,new HashMap<>());
                                        }
                                        CGMethodMap.get(body).put(invokeExpr,newCalleeSig);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    public static String mapIPCCalleeMethod(String calleeSig) {
        SootMethod sootMethod = methodSignatureMapSootMethod.get(calleeSig);
        if (sootMethod == null){
            return calleeSig;
        }
        SootClass declaredClass = sootMethod.getDeclaringClass();
        String declaredClassName = declaredClass.getName();

        if (declaredClass.isInterface()){
            // e.g. <android.net.sip.ISipSession: android.net.sip.SipProfile getPeerProfile()>
            if (declaredClass.getInterfaceCount() >= 1 && declaredClass.getInterfaces().getFirst().getName().equals("android.os.IInterface")){
                if (ServiceInterfaces.frameworkRawInterfaceSigs.contains(StringUtil.addStubProxyInSig(calleeSig)))
                    return ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.get(StringUtil.addStubProxyInSig(calleeSig));
                if (stubClassNameMapImplClassName.containsKey(declaredClassName+"$Stub"))
                    return getReplacedMethodSig(calleeSig,declaredClassName,stubClassNameMapImplClassName.get(declaredClassName+"$Stub"));
                else
                    return null;
            }
        }
        return calleeSig;
    }

    public static String getReplacedMethodSig(String methodSig, String declaredClassName, String implClassName) {
        String implMethodSig = methodSig.replace(declaredClassName + ":", implClassName + ":");
        if (methodSignatureMapSootMethod.containsKey(implMethodSig))
            return implMethodSig;
        else {
            return methodSig;
        }
    }

    public static boolean isBaseClassMethod(String methodSig){
        return methodSignatureMapSootMethod.containsKey(methodSig) && isBaseClassMethod(methodSignatureMapSootMethod.get(methodSig));
    }
    // Method only contains exception. E.g. com.android.server.wifi.BaseWifiService
    public static boolean isBaseClassMethod(SootMethod sootMethod){
        try{
            Body body = sootMethod.retrieveActiveBody();
            UnitPatchingChain unitPatchingChain = body.getUnits();
            if (unitPatchingChain.size() - sootMethod.getParameterCount()-1 == 3 && unitPatchingChain.getLast() instanceof ThrowStmt){
                return true;
            }
        }catch (Exception e){
        }
        return false;
    }

    public static HashSet<String> getImplMethodSigsFromSonClasses(SootMethod sootMethod){
        String sourceMethodSig = sootMethod.getSignature();
        return getImplMethodSigsFromSonClasses(sourceMethodSig);
    }

    public static HashSet<String> getImplMethodSigsFromSonClasses(String sourceMethodSig){
        String declaredClassName = StringUtil.getDeclareClassFromMethodSig(sourceMethodSig);
        HashSet<String> implMethodSigs = new HashSet<>();
        if (fatherClassNameMapSonClassNames.containsKey(declaredClassName)){
            for (String sonClassName:fatherClassNameMapSonClassNames.get(declaredClassName)){
                String tmpSig = StringUtil.replaceDeclaredClassOfMethodSig(sourceMethodSig,sonClassName);
                if (methodSignatureMapSootMethod.containsKey(tmpSig)){
                    SootMethod tmpMethod = methodSignatureMapSootMethod.get(tmpSig);
                    if (tmpMethod.isConcrete() && !isBaseClassMethod(tmpMethod))
                        implMethodSigs.add(tmpSig);
                    else
                        implMethodSigs.addAll(getImplMethodSigsFromSonClasses(tmpMethod));
                }
            }
        }
        return implMethodSigs;
    }

    public static boolean isHandler(SootClass sootClass){
        if (sootClass.getName().equals("android.os.Handler"))
            return true;
        while (sootClass.hasSuperclass()){
            sootClass = sootClass.getSuperclass();
            if (sootClass.getName().equals("android.os.Handler"))
                return true;
        }
        return false;
    }


    public static String getCalleeOnCG(Body body,InvokeExpr invokeExpr){
        if (CGMethodMap.containsKey(body) && CGMethodMap.get(body).containsKey(invokeExpr)){
            return CGMethodMap.get(body).get(invokeExpr);
        }
        String callerMethod = body.getMethod().getSignature();
        String invokeSig = invokeExpr.getMethodRef().getSignature();
        if (callerMethodSignatureMapCalleeMethodSignatures.containsKey(callerMethod)){
            if (callerMethodSignatureMapCalleeMethodSignatures.get(callerMethod).contains(invokeSig)){
                return invokeSig;
            }else{
                for (String callee:callerMethodSignatureMapCalleeMethodSignatures.get(callerMethod)){
                    if (StringUtil.getMethodNameFromMethodSig(callee).equals(StringUtil.getMethodNameFromMethodSig(invokeSig))
                            && Arrays.equals(StringUtil.extractMethodParamArrayFromMethodSig(callee),StringUtil.extractMethodParamArrayFromMethodSig(invokeSig)))
                        return callee;
                }
            }
        }
        return invokeSig;
    }


}
