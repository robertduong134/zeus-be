package vn.com.vetc.zeus.common;

public class AppException extends RuntimeException{
    private String code;

    public AppException(String code, String msg, Object... params){
        super(String.format(msg, params));

        this.code = code;
    }

    public AppException(String code, String msg){
        super(msg);
        this.code = code;
    }

    public AppException(String msg, Object... params){
        this(null, msg, params);
    }

    public AppException(String msg, Object param){
        this(null, msg, new Object[] {param});
    }

    public AppException(String msg){
        super(msg);
    }

    public String getCode() {
        return code;
    }
}
