package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

import com.google.gson.Gson;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {


    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private final Gson g = new Gson();

    public LoginResource() {

    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data) {
        LOG.fine("Login attempt by user: " + data.username);
        //Step 1:
        //return Response.ok().build();

        //Step 2:
        //return Response.ok(new AuthToken(data.username)).build();

        //Step 3:
        if (data.username.equals("hj") && data.password.equals("password")) {
            AuthToken at = new AuthToken(data.username);
            return Response.ok(g.toJson(at)).build();
        }
        return Response
                .status(Response.Status.FORBIDDEN)
                .entity("Incorrect Username or password")
                .build();
    }

    @GET
    @Path("/{username}")
    public Response checkUsernameAvailable(@PathParam("username") String username) {
		if(username.trim().equals("hj")) {
            return Response.ok().entity(g.toJson(false)).build();
        }
        else {
            return Response.ok().entity(g.toJson(true)).build();
        }
    }

}
