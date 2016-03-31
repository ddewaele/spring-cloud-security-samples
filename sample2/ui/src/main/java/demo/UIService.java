package demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/uiservice")
public class UIService {


    @RequestMapping("/publicService")
    public ServiceResponse publicService() {
        return new ServiceResponse("public");
    }

    @RequestMapping("/authenticatedService")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ServiceResponse authenticatedService() {
        return new ServiceResponse("authenticated");
    }

    @RequestMapping("/userService")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ServiceResponse userService() {
        return new ServiceResponse("user");
    }

    @RequestMapping("/managerService")
    @PreAuthorize("hasRole('ROLE_MANAGER')")
    public ServiceResponse managerService() {
        return new ServiceResponse("manager");
    }

    @RequestMapping("/adminService")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ServiceResponse adminService() {
        return new ServiceResponse("admin");
    }

    class ServiceResponse {
        private String msg;

        ServiceResponse(String msg) {
            this.msg=msg;
        }

        public String getMsg() {
            return msg;
        }
    }

}