package InputKnowledge;

import com.alibaba.fastjson.JSONObject;

import java.util.*;

public class ArgumentScope{
    public String argType;
    public String argName;
    public HashMap<Object, Integer> staticScope;
    public HashMap<Object, Integer> dynamicScope;
    public HashMap<Object, Integer> unkownScope;
    public ArrayList<ArgumentScope> subFields = new ArrayList<>();

    public ArgumentScope(String type, String name){
        argName = name;
        argType = type;
        staticScope = new HashMap<>();
        dynamicScope = new HashMap<>();
        unkownScope = new HashMap<>();
    }

    public void addStaticValue(Object value){
        if(staticScope.containsKey(value)) staticScope.put(value, staticScope.get(value)+1);
        else staticScope.put(value,1);
    }

    public void addDynamicValue(Object value){
        if(dynamicScope.containsKey(value)) dynamicScope.put(value, dynamicScope.get(value)+1);
        else dynamicScope.put(value,1);
    }

    public void addUnkownValue(Object value){
        if(unkownScope.containsKey(value)) unkownScope.put(value, unkownScope.get(value)+1);
        else unkownScope.put(value,1);
    }

    public void addFiled(ArgumentScope filed){
        for(ArgumentScope subField: subFields){
            if(subField.argName.equals(filed.argName) && subField.argType.equals(filed.argType))
                return;
        }
        subFields.add(filed);
    }

    public String getFieldName(ArgumentScope field){
        if(this==field)
            return this.argName;
        String name = "";
        for(ArgumentScope sub : subFields){
            if(!sub.getFieldName(field).equals("")) {
                name = name + "." + sub.getFieldName(field);
                break;
            }
        }
        return name;
    }

    public boolean isSubField(ArgumentScope arg){
        for(ArgumentScope child: subFields){
            if(child == arg)
                return true;
            else if(child.isSubField(arg))
                return true;
        }
        return false;
    }

    public Set<Object> getValues(String type){
        if(type.equals("Static"))
            return staticScope.keySet();
        if(type.equals("Dynamic"))
            return dynamicScope.keySet();
        else {
            HashSet<Object> totalScope = new HashSet<>();
            totalScope.addAll(staticScope.keySet());
            totalScope.addAll(dynamicScope.keySet());
            return totalScope;
        }
    }

    public ArgumentScope getField(String subName, String subType){
        if(this.argName.equals(subName) && this.argType.equals(subType))
            return this;
        for(ArgumentScope subField: subFields){
            if(subField.getField(subName,subType)!=null)
                return subField.getField(subName,subType);
        }
        return null;
    }

    public String toString(){
        HashMap<String,Object> desc = new HashMap<>();
        desc.put("Name",this.argName);
        desc.put("Type",this.argType);
        desc.put("CurrentScope",this.getValues("Total").toString());
        String fields = "";
        for(ArgumentScope field : this.subFields){
            fields+=field.toString();
        }
        desc.put("SubFiedls",fields);
        return desc.toString();
    }

    public int scopeSize(){
        int size = 0;
        size += staticScope.size()+dynamicScope.size()+unkownScope.size();
        for(ArgumentScope filed:subFields){
            size += filed.scopeSize();
        }
        return size;
    }

    public JSONObject getScope(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("staticScope",staticScope);
        jsonObject.put("dynamicScope",dynamicScope);
        jsonObject.put("unkownScope",unkownScope);
        ArrayList<JSONObject> filedScopes = new ArrayList<>();
        for(ArgumentScope field: subFields){
            filedScopes.add(field.getScope());
        }
        jsonObject.put("FieldScope",filedScopes);
        return jsonObject;
    }
}
