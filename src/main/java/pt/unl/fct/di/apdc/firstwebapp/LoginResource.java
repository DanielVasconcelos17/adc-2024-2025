package pt.unl.fct.di.apdc.firstwebapp;

import java.util.logging.Logger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    public LoginResource(){}

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data){
        LOG.fine("Login attempt by user: " + data.username);
        //Step 1:
        //return Response.ok().build();

        //Step 2:
        return Response.ok(new AuthToken(data.username)).build();

        //Step 3:
    }
}
