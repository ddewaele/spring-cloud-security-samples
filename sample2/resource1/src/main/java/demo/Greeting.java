package demo;

/**
 * Created by ddewaele on 10/04/16.
 */
public class Greeting {

    public Greeting() {
    }

    public Greeting(String id, String message) {
        this.id = id;
        this.message = message;
    }

    private String id;
    private String message;


    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
