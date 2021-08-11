package InputKnowledge;

import analysis.callChainsExtractor.CG;
import analysis.riskyMethodsLocater.SearchRootSet;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import fj.Hash;
import main.Memory;
import serviceInterfaces.ParamInfoExtractor;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import util.StringUtil;
import util.TimeMeasurement;

import java.util.*;


public class MethodScope {
    public SootMethod method;
    public Body body;
    public String methodSignature;


    public HashMap<Local, ArgumentScope> scopes = new HashMap<>();
    public HashMap<ArgumentScope,HashMap> argMapNextLayer = new HashMap<>();

    private int depth;
    private int MAX_DEPTH = 100;
    private boolean isvalid = true;

    private HashMap<String, MethodScope> nextLayer = new HashMap<>();

    private ArrayList<Node> DFGEntries = new ArrayList<>();


    public MethodScope(String methodSignature, ArrayList<Integer> paramsMap,int currentDepth){
        method = Memory.methodSignatureMapSootMethod.get(methodSignature);
        if(method==null)
            method = Memory.load_method(methodSignature);
        depth = currentDepth;
        this.methodSignature = methodSignature;
        if(method!=null){
            try {
                body = method.retrieveActiveBody();
            }catch (Exception e){
                isvalid = false;
            }
        }else isvalid = false;

        if(!isvalid)
            return;

        ParamInfoExtractor.getParamNameForMethod(methodSignature);

        ArrayList<Local> params = map2Local(paramsMap);
        ArrayList<Local> paramsTotal = new ArrayList<>(body.getParameterLocals());

        for(Local param: params){
            try {
                String argType = param.getType().toString();
                String argName = ParamInfoExtractor.getInterfaceParamNames(methodSignature, paramsTotal.indexOf(param));

                ArgumentScope argScope = new ArgumentScope(argType, argName);
                scopes.put(param, argScope);
                argMapNextLayer.put(argScope, new HashMap());
            }catch (Exception e){
                e.printStackTrace();
                System.out.println(methodSignature);
                System.exit(-1);
            }
        }
    }

    public void addArg(int index, String argName){
        if(!isvalid)
            return;
        Local param = map2Local(null).get(index);
        if(scopes.containsKey(param))
            return;

        String argType = param.getType().toString();
        ArgumentScope argumentScope = new ArgumentScope(argType,argName);
        scopes.put(param, argumentScope);
        argMapNextLayer.put(argumentScope, new HashMap());

    }

    public Node value2LatestNode(Value value, int sequence){
        HashSet<Node> allNodes = BFS();
        Node result = null;
        for(Node current: allNodes){
            if(!current.valueEquals(value) || current.sequence >= sequence)
                continue;
            if(result==null)
                result = current;
            else result = newestNode(result,current);
        }
        return result;
    }

    public Node newestNode(Node nod1, Node node2){
        return nod1.sequence>node2.sequence? nod1 : node2;
    }

    public HashSet<Node> BFS(){
        HashSet<Node> result = new HashSet<>();
        for(Node node: DFGEntries)
            result.addAll(node.findAllInfectors());
        return result;
    }


    public void init(){
        if(InputScope.visitedMethod.contains(this.methodSignature))
            return;
        else
            InputScope.visitedMethod.add(this.methodSignature);
        if(!this.isvalid)
            return;

        int sequence = 0;
        for(Unit unit : body.getUnits()) {
            sequence +=1;
            if(unit==null)
                continue;
            try {
                if (unit instanceof IfStmt) {
                        processIfStmt(unit, sequence);
                } else if (unit instanceof JAssignStmt) {
                    processAssignmentStmt(unit, sequence);
                } else if (unit instanceof JInvokeStmt) {
                    processInvokeStmt(unit, sequence);
                }else if(unit instanceof JIdentityStmt){
                    processIdentityStmt((JIdentityStmt) unit);
                }
            }catch (Exception e){
                e.printStackTrace();
                System.out.println("Error in dealing: "+unit.toString()+";"+sequence);
                System.exit(-1);
            }
        }

    }

    public void visitMethod(InvokeExpr invokeExpr, Node leftNode, int sequence) throws Exception{
        if(invokeExpr == null)
            throw new Exception("Called visitMethod with null invokeExpr");
        String nextSig = CG.getCalleeOnCG(this.body,invokeExpr);

        Node callerNode = null;
        if(!(invokeExpr instanceof JStaticInvokeExpr)){
            Value caller = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue();
            callerNode = value2LatestNode(caller, sequence);

        }

        if(SearchRootSet.isIterableType(StringUtil.getDeclareClassFromMethodSig(nextSig))){
            if("get|peek|pool|".contains(StringUtil.getMethodNameFromMethodSig(nextSig))){
                if(callerNode!=null && leftNode != null) {
                    callerNode.infect(leftNode);
                    return;
                }
            }
        }
        MethodScope nextMethod = null;
        if(!nextLayer.containsKey(nextSig)){
            ArrayList<Integer> argsMap;
            int argLength = invokeExpr.getArgs().size();
            argsMap = new ArrayList<>();
            for(int i=0; i<argLength;i++) argsMap.add(0);
            nextMethod = new MethodScope(nextSig, argsMap, depth+1);
            nextLayer.put(nextSig, nextMethod);
        }else {
            nextMethod = nextLayer.get(nextSig);
        }
        boolean isPolluted = false;
        for(Value right : invokeExpr.getArgs()){
            Node rightNode = value2LatestNode(right, sequence);
            if(rightNode==null || !rightNode.isPolluted())
                continue;
            Node taintNode = rightNode;
            isPolluted = true;
            if(InputScope.specialInvoke.contains(nextSig))
                return;

            if(InputScope.infectInvoke.contains(nextSig)){
                if(callerNode!=null)
                    taintNode.infect(callerNode);
                if(leftNode!=null)
                    taintNode.infect(leftNode);
                continue;
            }

            int location = invokeExpr.getArgs().indexOf(right);
            if(location!=-1){
                nextMethod.addArg(location, taintNode.getName());
                addArgTaintMap(right,sequence,nextSig,location);
            }
            if(leftNode!= null){
                taintNode.infect(leftNode);
            }

        }

        if(isPolluted)
            nextMethod.init();

        if(callerNode!=null){

            for(int index : nextMethod.infectedByLocalArg()){
                Node rightNode = value2LatestNode(invokeExpr.getArg(index),sequence);
                if(rightNode==null || !rightNode.isPolluted())
                    continue;
                rightNode.infect(callerNode);
            }

            if(leftNode!=null && callerNode.isPolluted()) {
                callerNode.infect(leftNode);
            }
        }

    }

    public ArrayList<Integer> infectedByLocalArg(){
        ArrayList<Integer> locations = new ArrayList<>();
        if(!this.isvalid)
            return locations;
        for(Node valueNode : BFS()){
            if(!(valueNode.currentValue instanceof Local))
                continue;
            if (this.body.getParameterLocals().contains(valueNode.currentValue))
                continue;
            if(!valueNode.isPolluted())
                continue;

            for(Node root : valueNode.findPatientZero()){
                if(root.sequence == 0 && this.body.getParameterLocals().contains(root.currentValue) ) {
                    int index = this.body.getParameterLocals().indexOf(root.currentValue);
                    if(!locations.contains(index))
                        locations.add(index);
                }
            }
        }
        return locations;
    }

    public ArrayList<ArgumentScope> fetchScopes(){

        ArrayList<ArgumentScope> total_scopes = new ArrayList<>(scopes.values());

        for(String childMethod: nextLayer.keySet()){
            MethodScope nextScope = nextLayer.get(childMethod);
            total_scopes.addAll(nextScope.fetchScopes());
        }
        return total_scopes;
    }

    public JSONObject mergeScope(ArrayList<String> allowedMethod){
        JSONObject result = new JSONObject();

        for(ArgumentScope argScope : argMapNextLayer.keySet()){
            String argname = "null";
            if(scopes.containsValue(argScope)){
                int location = getArgIndex(argScope);
                argname = String.valueOf(location);
            }else{
                for(ArgumentScope root:scopes.values()){
                    String tmp = root.getFieldName(argScope);
                    if(tmp.equals(""))
                        continue;
                    argname = String.valueOf(getArgIndex(root))+tmp.substring(tmp.indexOf("."));
                    break;
                }
            }
            if(!result.containsKey(argname))
                result.put(argname, new HashSet<String>());
            HashSet<String> scopeValues = result.getObject(argname, HashSet.class);

            HashMap<String,ArrayList<Integer>> nextMap = argMapNextLayer.get(argScope);
            for(String nextSig: nextMap.keySet()){
                MethodScope next = nextLayer.get(nextSig);
                for(int index:nextMap.get(nextSig))
                    scopeValues.addAll(next.getArgScopes(index, allowedMethod));
            }

            if(allowedMethod!=null && !allowedMethod.contains(this.methodSignature))
                continue;
            for(Object value: argScope.getValues("Total")){
                scopeValues.add(value.toString());
            }
        }
        for(ArgumentScope arg:this.scopes.values()){
            String index = String.valueOf(getArgIndex(arg));
            if(!result.containsKey(index)){
                HashSet<String> scopeValues = new HashSet<>();
                if(allowedMethod==null || allowedMethod.contains(this.methodSignature)){
                    for(Object value:arg.getValues("Total")){
                        scopeValues.add(value.toString());
                    }
                }
                result.put(index,scopeValues);
            }
        }

        return result;
    }

    public HashSet<String> getArgScopes(int index, ArrayList<String> allowedMethod){
        HashSet<String> result = new HashSet<>();
        if(!isvalid)
            return result;
        ArgumentScope argumentScope = indexToArg(index);
        if(argumentScope == null)
            return result;
        for(ArgumentScope argScope : argMapNextLayer.keySet()){
            if(argScope != argumentScope)
                continue;
            HashMap<String, ArrayList<Integer>> map = argMapNextLayer.get(argScope);
            for(String nextSig:map.keySet()){
                MethodScope nextMethod = nextLayer.get(nextSig);
                for(int nextIndex:map.get(nextSig)) {
                    result.addAll(nextMethod.getArgScopes(nextIndex, allowedMethod));
                }
            }
        }
        if(allowedMethod!=null && !allowedMethod.contains(this.methodSignature))
            return result;
        for(Object value : argumentScope.getValues("Total"))
            result.add(value.toString());
        return result;
    }

    public ArrayList<String> getRiskyInputs(String riskyMethod){
        ArrayList<String> result = new ArrayList<>();
        if(riskyMethod.equals(this.methodSignature)){
            for(ArgumentScope arg:this.scopes.values()){
                int location = getArgIndex(arg);
                result.add(String.valueOf(location));
            }
            return result;
        }
        for(ArgumentScope arg:this.argMapNextLayer.keySet()){
            String argname = "null";
            if(scopes.containsValue(arg)){
                int location = getArgIndex(arg);
                argname = String.valueOf(location);
            }else{
                for(ArgumentScope root:scopes.values()){
                    String tmp = root.getFieldName(arg);
                    if(tmp.equals(""))
                        continue;
                    argname = String.valueOf(getArgIndex(root))+tmp.substring(tmp.indexOf("."));
                    break;
                }
            }
            if(isTaintToRisky(arg, riskyMethod))
                result.add(argname);
        }
        return result;
    }

    public boolean isTaintToRisky(ArgumentScope arg, String riskySig){
        if(!argMapNextLayer.containsKey(arg) || !this.isvalid)
            return false;
        HashMap<String, ArrayList<Integer>> methodMaps = argMapNextLayer.get(arg);
        for(String methodSig: methodMaps.keySet()){
            if(methodSig.equals(riskySig))
                return true;
            ArrayList<Integer> positionMap = methodMaps.get(methodSig);
            MethodScope next = nextLayer.get(methodSig);
            if(!next.isvalid)
                continue;
            for(int index:positionMap){
                if(next.isTaintToRisky(next.indexToArg(index),riskySig))
                    return true;
            }
        }
        return false;
    }

    public Set<Local> getTaintedLocalsInTargetMethod(String riskyMethodSig){
        if (this.methodSignature.equals(riskyMethodSig)){
            return this.scopes.keySet();
        }
        for (String callerMethodSig:this.nextLayer.keySet()){
            MethodScope callerMethodScope = this.nextLayer.get(callerMethodSig);
            Set<Local> res = callerMethodScope.getTaintedLocalsInTargetMethod(riskyMethodSig);
            if (res.size()>0)
                return res;
        }
        return new HashSet<>();
    }

    private ArgumentScope indexToArg(int index){
        Value target = body.getParameterLocals().get(index);
        return scopes.getOrDefault(target,null);
    }

    private int getArgIndex(ArgumentScope arg){
        for(Value local:scopes.keySet()){
            if(scopes.get(local) == arg){
                return body.getParameterLocals().indexOf(local);
            }
        }
        return -1;
    }

    private void addArgTaintMap(Value taint, int sequence, String methodSig, int location){
        Node tmp = value2LatestNode(taint, sequence);
        Node father = tmp.findDirectFather();
        HashSet<Node> roots = tmp.findPatientZero();
        for(Node root: roots){
            if(!scopes.containsKey(root.currentValue))
                continue;
            ArgumentScope arg = scopes.get(root.currentValue);
            ArgumentScope taintArg ;
            if(father == root)
                taintArg = arg;
            else {
                taintArg = arg.getField(father.getName(), father.getType());
                if(taintArg == null) taintArg = arg;
            }
            if(!argMapNextLayer.containsKey(taintArg)){
                argMapNextLayer.put(taintArg, new HashMap());
            }
            HashMap<String, ArrayList<Integer>> taintMap = argMapNextLayer.get(taintArg);
            if(!taintMap.containsKey(methodSig)) taintMap.put(methodSig, new ArrayList<>());
            ArrayList<Integer> positionMap = taintMap.get(methodSig);
            if(!positionMap.contains(location)) positionMap.add(location);
        }
    }

    private void processIdentityStmt(JIdentityStmt jIdentityStmt){
        Value identity = jIdentityStmt.leftBox.getValue();
        Node thisNode;
        if(scopes.containsKey(identity)){
            thisNode = new Node(identity, null, 0, 3);
        }else
            thisNode = new Node(identity, null, 0, 0);
        DFGEntries.add(thisNode);
    }

    private void processIfStmt(Unit unit, int sequence) throws Exception{
        ConditionExpr expr = (ConditionExpr)((IfStmt) unit).getConditionBox().getValue();
        Value op1 = expr.getOp1();
        Value op2 = expr.getOp2();
        op1 = Op2Value(op1);
        op2 = Op2Value(op2);
        if(op1==null || op2 == null)
            return;

        Node op1Node = value2LatestNode(op1,sequence);
        Node op2Node = value2LatestNode(op2,sequence);
        if((op1Node == null || !op1Node.isPolluted()) && (op2Node==null || !op2Node.isPolluted()))
            return;

        if(op1 instanceof Constant || op2 instanceof Constant || (op1Node!=null && op1Node.tag==1) || (op2Node!=null && op2Node.tag==1)){
            Value constant = (op1 instanceof Constant||(op1Node!=null && op1Node.tag==1)) ? op1 : op2;
            Value taint = (op1 == constant) ? op2 : op1;
            Node constantNode = value2LatestNode(constant, sequence);

            Node taintNode = value2LatestNode(taint, sequence);
            if (taintNode == null){
                throw new Exception("Error in finding lated Node");
            }
            HashSet<Node> roots = taintNode.findPatientZero();

            if(scopes.containsKey(taintNode.currentValue)){
                scopes.get(taintNode.currentValue).addStaticValue(constant.toString());
            }else{
                JAssignStmt edge = taintNode.transmissionRoute;
                if(edge.containsInvokeExpr()){
                    String methodSig = taintNode.transmissionRoute.getInvokeExpr().getMethodRef().getSignature();
                    if(InputScope.specialInvoke.contains(methodSig)){
                        List<ValueBox> test = edge.getInvokeExpr().getUseBoxes();
                        Value targetStr, taintStr;
                        Node targetStrNode, taintStrNode;
                        Node tmp = value2LatestNode(test.get(0).getValue(),taintNode.sequence);
                        if(tmp==null||!tmp.isPolluted()) {
                            targetStr = test.get(0).getValue();
                            taintStr = test.get(1).getValue();
                            targetStrNode = tmp;
                            taintStrNode = value2LatestNode(taintStr, taintNode.sequence);
                        }
                        else{
                            targetStr = test.get(1).getValue();
                            taintStr = test.get(0).getValue();
                            targetStrNode = value2LatestNode(targetStr, taintNode.sequence);
                            taintStrNode = tmp;
                        }

                        if(targetStrNode!=null && targetStrNode.tag==1){
                            if(roots.size()!=1)
                                System.out.println("Error in finding parent!"+ unit.toString()+";"+sequence);
                            addValueThroughNode(taintStrNode, "Static", targetStrNode.getValue());
                        }else if(targetStr instanceof Constant){
                            addValueThroughNode(taintStrNode, "Static", targetStr.toString());
                        }
                        else{
                            addValueThroughNode(taintStrNode, "Static", targetStr.toString());
                            System.out.println("String: Unkown;"+unit.toString()+";"+sequence);
                        }
                    }else if(depth >= MAX_DEPTH-1){
                        addValueThroughNode(taintNode, "Dynamic", methodSig);
                    }
                }
                else if(edge.containsFieldRef()){
                    addValueThroughNode(taintNode,"Static",constant.toString());
                }else{
                    if(edge.rightBox.getValue() instanceof BinopExpr){
                        Value cmp1 = ((BinopExpr) edge.rightBox.getValue()).getOp1();
                        Node cmp1Node = value2LatestNode(cmp1, taintNode.sequence);
                        Value cmp2 = ((BinopExpr) edge.rightBox.getValue()).getOp2();
                        Node cmp2Node = value2LatestNode(cmp2, taintNode.sequence);
                        if(cmp1Node!=null&&cmp1Node.isPolluted() && (cmp2Node==null || !cmp2Node.isPolluted())){
                            if(cmp2 instanceof Constant){
                                addValueThroughNode(taintNode,"Static", cmp2.toString());
                            }else if(cmp2Node!=null && cmp2Node.tag==1){
                                addValueThroughNode(taintNode,"Static", cmp2Node.getValue());
                            }else if(cmp2Node!=null && cmp2Node.tag==2){
                                addValueThroughNode(taintNode, "Dynamic", cmp2Node.getValue());
                            }else if(cmp2Node!=null && cmp2Node.tag == 0){
                                addValueThroughNode(taintNode, "Unkown", cmp2Node.getValue());
                            } else{
                                throw new Exception("fuck cmp");
                            }
                        }else if(cmp2Node != null && cmp2Node.isPolluted() && (cmp1Node==null || !cmp1Node.isPolluted())){
                            if(cmp1 instanceof Constant){
                                addValueThroughNode(taintNode,"Static", cmp1.toString());
                            }else if(cmp1Node!=null && cmp1Node.tag==1){
                                addValueThroughNode(taintNode,"Static", cmp1Node.getValue());
                            }else if(cmp1Node!=null && cmp1Node.tag==2){
                                addValueThroughNode(taintNode, "Dynamic", cmp1Node.getValue());
                            }else if(cmp1Node!=null && cmp1Node.tag == 0){
                                addValueThroughNode(taintNode, "Unkown", cmp1Node.getValue());
                            } else{
                                throw new Exception("fuck cmp");
                            }
                        }else{
                            System.out.println("Taint vs Taint: "+unit.toString()+";"+sequence);
                        }
                    }
                    addValueThroughNode(taintNode, "Static", constant.toString());
                }
            }
        }else{
            if(!op1Node.isPolluted()||!op2Node.isPolluted()){
                Node taint = op1Node.isPolluted()? op1Node : op2Node;
                Node invokeResult = op1Node.isPolluted()? op2Node : op1Node;
                if(taint.transmissionRoute!=null && taint.transmissionRoute.containsInvokeExpr())
                    addValueThroughNode(taint, "Dynamic", taint.getValue());
                else{
                    if(invokeResult.tag==2)
                        addValueThroughNode(taint, "Dynamic", invokeResult.getValue());
                    else
                        addValueThroughNode(taint,"Unkown", invokeResult.getValue());
                }
            }else{
                Node taint1 = value2LatestNode(op1, sequence);
                Node taint2 = value2LatestNode(op2, sequence);
                if(taint1!=null && taint2!=null){
                    if(scopes.containsKey(taint1.currentValue))
                        if(taint2.transmissionRoute!=null && taint2.transmissionRoute.containsInvokeExpr())
                            addValueThroughNode(taint1,"Dynamic", taint2.getValue());
                    else if(scopes.containsKey(taint2.currentValue) )
                        if(taint1.transmissionRoute!=null && taint1.transmissionRoute.containsInvokeExpr())
                            addValueThroughNode(taint2,"Dynamic", taint1.getValue());
                    else
                        if(depth >= MAX_DEPTH-1){
                            if(taint1.transmissionRoute!=null && taint1.transmissionRoute.containsInvokeExpr()){
                                addValueThroughNode(taint2, "Dynamic", taint1.getValue());
                            }else{
                                System.out.println("Changed: no invoke: "+unit.toString());
                            }

                            if(taint2.transmissionRoute!=null && taint2.transmissionRoute.containsInvokeExpr()){
                                addValueThroughNode(taint1, "Dynamic", taint2.getValue());
                            }else{
                                System.out.println("Changed: no invoke: "+unit.toString());
                            }
                        }
                }
            }
        }
    }

    private void processAssignmentStmt(Unit unit, int sequence) throws Exception{
        JAssignStmt assignStmt = (JAssignStmt) unit;
        Value left = Op2Value(assignStmt.leftBox.getValue());
        Node currentNode = new Node(left,assignStmt,sequence,0);
        Value right = assignStmt.rightBox.getValue();

        if(assignStmt.containsInvokeExpr()){

            visitMethod(assignStmt.getInvokeExpr(), currentNode, sequence);

            if(!currentNode.isPolluted()){
                currentNode.setType(2);
                DFGEntries.add(currentNode);
            }
        }else if (assignStmt.containsArrayRef()){
            Value caller = assignStmt.getArrayRef().getBase();
            Node callerNode = value2LatestNode(caller, sequence);
            if(callerNode!=null)
                callerNode.infect(currentNode);
            else {
                currentNode.setType(1);
                DFGEntries.add(currentNode);
            }
        }else if(assignStmt.containsFieldRef()){
            String filedType = assignStmt.getFieldRef().getField().getType().toString();
            String filedName = assignStmt.getFieldRef().getField().getName();
            ArgumentScope field = new ArgumentScope(filedType,filedName);

            if(assignStmt.getFieldRef().getUseBoxes().size()==0) {
                currentNode.setType(1);
                DFGEntries.add(currentNode);
            }else {
                if (assignStmt.leftBox.getValue() instanceof FieldRef) {
                    ArrayList<Value> rights = new ArrayList<>();
                    if(right instanceof Expr && right.getUseBoxes().size()>0){
                        for(ValueBox vB: right.getUseBoxes())
                            rights.add(vB.getValue());
                    }else{
                        rights.add(right);
                    }
                    for(Value v:rights){
                        Node rightNode = value2LatestNode(v, sequence);
                        if(rightNode!=null && rightNode.isPolluted())
                            rightNode.infect(currentNode);
                    }
                } else {
                    Value caller = assignStmt.getFieldRef().getUseBoxes().get(0).getValue();
                    Node callerNode = value2LatestNode(caller, sequence);
                    if(callerNode==null) {
                        currentNode.setType(1);
                        DFGEntries.add(currentNode);
                        throw new Exception("Empty node with caller!");
                    }
                    else {
                        callerNode.infect(currentNode);
                        Node directed = callerNode.findDirectFather();
                        if (directed != null && scopes.containsKey(directed.currentValue)) {
                            scopes.get(directed.currentValue).addFiled(field);
                        }
                    }
                }
            }
        }else{
            ArrayList<Value> rights = new ArrayList<>();
            if(right instanceof Expr && right.getUseBoxes().size()>0){
                for(ValueBox vB: right.getUseBoxes())
                    rights.add(vB.getValue());
            }else{
                rights.add(right);
            }
            for(Value v:rights){
                Node rightNode = value2LatestNode(v, sequence);
                if(rightNode!=null && rightNode.isPolluted())
                    rightNode.infect(currentNode);
            }
            if(!currentNode.isPolluted()){
                Node rightNode = value2LatestNode(right, sequence);
                if(rightNode!=null){
                    rightNode.infect(currentNode);
                }else{
                    if(right instanceof Expr){
                        currentNode.setType(2);
                    }else if(right instanceof Constant){
                        currentNode.setType(1);
                    }
                }
                DFGEntries.add(currentNode);
            }
        }
    }

    private void processInvokeStmt(Unit unit, int sequence) throws Exception{
        JInvokeStmt invokeStmt = (JInvokeStmt) unit;
        InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();

        visitMethod(invokeExpr, null, sequence);

    }

    private ArrayList<Local> map2Local(ArrayList<Integer> argsMap){
        ArrayList<Local> params = new ArrayList<>();
        if(body==null)
            return params;
        ArrayList<Local> locals = new ArrayList<>(body.getParameterLocals());
        if(argsMap==null) return locals;
        for(int i=0;i<argsMap.size();i++){
            if(argsMap.get(i)==1){
                params.add(locals.get(i));
            }
        }
        return params;
    }

    private Value Op2Value(Value value){
        if(value instanceof NullConstant)
            return null;
        if(value.getUseBoxes().size()>0){
            return value.getUseBoxes().get(0).getValue();
        }
        return value;
    }

    private void addValueThroughNode(Node taint,String valueType, Object value){
        HashSet<Node> roots = taint.findPatientZero();
        Node directFather = taint.findDirectFather();
        String taintName;
        taintName = directFather.currentValue.toString();
        String taintType = directFather.currentValue.getType().toString();
        for (Node root: roots){
            if(!scopes.containsKey(root.currentValue))
                continue;
            ArgumentScope arg = scopes.get(root.currentValue);
            if(arg.getField(taintName, taintType)!=null){
                if(valueType.equals("Static")){
                    arg.getField(taintName, taintType).addStaticValue(value);
                }else if(valueType.equals("Dynamic"))
                    arg.getField(taintName, taintType).addDynamicValue(value);
                else{
                    arg.getField(taintName, taintType).addUnkownValue(value);
                }
            }else{
                if(valueType.equals("Static")){
                    arg.addStaticValue(value);
                }else if(valueType.equals("Dynamic"))
                    arg.addDynamicValue(value);
                else{
                    arg.addUnkownValue(value);
                }
            }
        }
    }

    public class Node{
        public ArrayList<Node> infetctionSource = new ArrayList<>();
        public JAssignStmt transmissionRoute;
        public Value currentValue;
        public ArrayList<Node> susceptableValues = new ArrayList<>();
        public int sequence;
        public int tag;

        Node(Value current, JAssignStmt route, int unitNumber, int nodeType){
            currentValue = current;
            transmissionRoute = route;
            sequence = unitNumber;
            tag = nodeType;
        }

        public void setType(int nodeType){
            tag = nodeType;
        }

        public void infect(Node node){
            susceptableValues.add(node);
            node.infectedBy(this);
            if(node.tag<this.tag)
                node.setType(this.tag);
        }

        private void infectedBy(Node node){
            infetctionSource.add(node);
        }

        public ArrayList<Node> findInfectors(){
            return susceptableValues;
        }

        public boolean isPolluted(){
            return this.tag==3;
        }

        public HashSet<Node> findAllInfectors(){
            HashSet<Node> result = new HashSet<>();
            ArrayList<Node> queue = new ArrayList<>();
            queue.add(this);
            while(!queue.isEmpty()){
                Node current = queue.get(0);
                queue.remove(0);
                result.add(current);
                for(Node child:current.susceptableValues) {
                    if (!result.contains(child)) {
                        queue.add(child);
                    }
                }
            }
            return result;
        }

        public boolean valueEquals(Value value){
            return this.currentValue==value;
        }

        public HashSet<Node> findPatientZero(){
            HashSet<Node> result = new HashSet<>();
            HashSet<Node> visited = new HashSet<>();

            ArrayList<Node> queue = new ArrayList<>();
            queue.add(this);
            while(!queue.isEmpty()){
                Node current = queue.get(0);
                queue.remove(0);
                if(current.sequence==0 && scopes.containsKey(current.currentValue))
                    result.add(current);
                visited.add(current);
                for(Node parent:current.infetctionSource) {
                    if (!visited.contains(parent)) {
                        queue.add(parent);
                    }
                }
            }
            return result;
        }

        public Node findDirectFather(){
            if(this.infetctionSource.size()==0 || this.transmissionRoute==null || this.transmissionRoute.containsInvokeExpr() || this.transmissionRoute.containsFieldRef())
                return this;
            if(this.transmissionRoute.containsArrayRef())
                return infetctionSource.get(0);
            for(Node parent: infetctionSource){
                if(parent.findDirectFather()!=null)
                    return parent.findDirectFather();
            }
            return null;
        }

        public String getValue(){
            String result = "";
            if(this.tag == 0)
                if(this.transmissionRoute!=null)
                    result = this.transmissionRoute.rightBox.getValue().toString();
                else
                    result = this.currentValue.getType().getClass().getCanonicalName();
            else if(this.tag==1)
                if(this.infetctionSource.size()!=0)
                    for(Node parent:infetctionSource){
                        if(!parent.getValue().equals(""))
                            continue;
                        result += parent.getValue();
                    }
                else if(this.transmissionRoute!=null){
                    result = this.transmissionRoute.rightBox.getValue().toString();
                }else{
                    result = "unkown";
                }
            else if(this.tag==2)
                if(this.transmissionRoute.containsInvokeExpr())
                    result = transmissionRoute.getInvokeExpr().getMethodRef().getSignature();
                else{
                    if(this.infetctionSource.size()!=0)
                        for(Node parent: infetctionSource){
                            if(!parent.getValue().equals(""))
                                continue;
                            result += parent.getValue();
                        }
                    else if(this.transmissionRoute!=null){
                        result = this.transmissionRoute.rightBox.getValue().toString();
                    }else{
                        result = "unkown";
                    }
                }
            else
                result = "input";
            return result;
        }

        public String getName(){
            String name = "null";
            HashSet<Node> roots = this.findPatientZero();
            Node directFather = this.findDirectFather();
            String taintName;
            if(this.transmissionRoute!=null && this.transmissionRoute.containsFieldRef() && !DFGEntries.contains(this)){
                taintName = this.transmissionRoute.getFieldRef().getField().getName();
            }else{
                taintName = directFather.currentValue.toString();
            }

            String taintType = directFather.currentValue.getType().toString();
            for(Node root:roots){
                if(!root.isPolluted() || root.sequence!=0)
                    continue;
                ArgumentScope arg = scopes.get(root.currentValue);
                if(arg.getField(taintName, taintType)!=null){
                    name = arg.getField(taintName,taintType).argName;
                }else{
                    name = taintName;
                }
                break;
            }
            return name;
        }

        public String getType(){
            return this.currentValue.getType().toString();
        }
    }

}

