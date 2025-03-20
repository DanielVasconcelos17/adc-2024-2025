package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.google.gson.Gson;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;

import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

@Path("/register")
public class RegisterResource {

    private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    private final Gson g = new Gson();


    public RegisterResource() {}	// Default constructor, nothing to do

    @POST
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUserV1(LoginData data) {
        LOG.fine("Attempt to register user: " + data.username);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = Entity.newBuilder(userKey)
                .set("user_pwd", DigestUtils.sha512Hex(data.password))
                .set("user_creation_time", Timestamp.now())
                .build();
        datastore.put(user);
        LOG.info("User registered " + data.username);
        return Response.ok().entity(g.toJson(true)).build();
    }
}