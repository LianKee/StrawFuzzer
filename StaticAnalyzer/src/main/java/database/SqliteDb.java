package database;

import util.LogUtil;

import java.sql.*;


public class SqliteDb {

    public Connection connection = null;
    private Statement stmt = null;
    private String DB_PATH = "";

    public SqliteDb(String dpPath){
        DB_PATH=dpPath;
        try{
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:"+DB_PATH);
            System.out.println(connection.getAutoCommit());
        }catch (Exception e){
            System.err.println(e.getClass().getName()+":"+e.getMessage());
            e.printStackTrace();
            System.exit(0);
        }
    }

    public void executeUpdate(String sql){
        synchronized (DB_PATH){
            try{
                stmt = connection.createStatement();
                stmt.executeUpdate(sql);
            }catch (Exception e){
                System.err.println("Sql Error: "+sql);
                e.printStackTrace();
            }finally {
                if (stmt!=null){
                    try{
                        stmt.close();
                    }catch (SQLException e){
                        LogUtil.error("SqlUpdate",sql);
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public ResultSet select(String sql){
        ResultSet resultSet = null;
        try{
            stmt = connection.createStatement();
            resultSet = stmt.executeQuery(sql);
        }catch (SQLException e){
            e.printStackTrace();
        }
        return resultSet;
    }

    public boolean isClosed(){
        try{
            return connection!=null && connection.isClosed();
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    public void close(){
        if(!isClosed()){
            try{
                connection.close();
            }catch (SQLException e){
                e.printStackTrace();
            }
        }
    }

}
