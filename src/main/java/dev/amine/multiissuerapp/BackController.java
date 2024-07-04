package dev.amine.multiissuerapp;

// import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/back")
public class BackController {

    @GetMapping("/endpoint-public")
    public String internalEndpoint() {
        return "public endpoint";
    }

    @GetMapping("/endpoint-private")
    public String externalEndpoint() {
        return "private endpoint";
    }
}