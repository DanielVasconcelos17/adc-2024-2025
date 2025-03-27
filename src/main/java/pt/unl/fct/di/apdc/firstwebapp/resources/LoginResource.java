package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.logging.Logger;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Context;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

import com.google.gson.Gson;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

    private static final String MESSAGE_INVALID_CREDENTIALS = "Incorrect username or password.";
    private static final String MESSAGE_NEXT_PARAMETER_INVALID = "Request parameter 'next' must be greater or equal to 0.";


    private static final String LOG_MESSAGE_LOGIN_ATTEMP = "Login attempt by user: ";
    private static final String LOG_MESSAGE_LOGIN_SUCCESSFUL = "Login successful by user: ";
    private static final String LOG_MESSAGE_WRONG_PASSWORD = "Wrong password for: ";
    private static final String LOG_MESSAGE_UNKNOW_USER = "Failed login attempt for username: ";


    private static final String USER_PWD = "user_pwd";
    private static final String USER_LOGIN_TIME = "user_login_time";



    //Added recently TODO
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

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
                .status(Status.FORBIDDEN)
                .entity("Incorrect Username or password")
                .build();
    }

    @POST
    @Path("/v1b")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response doLoginV1b(LoginData data) {
        LOG.fine("Attempt to login user: " + data.username);

        Key userKey = userKeyFactory.newKey(data.username);

        Entity user = datastore.get(userKey);
        if( user != null ) {
            String hashedPWD = user.getString("user_pwd");
            if( hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
                KeyFactory logKeyFactory = datastore.newKeyFactory()
                        .addAncestor(PathElement.of("User", data.username))
                        .setKind("UserLog");
                Key logKey = datastore.allocateId(logKeyFactory.newKey());
                Entity userLog = Entity.newBuilder(logKey)
                        .set("user_login_time", Timestamp.now())
                        .build();
                datastore.put(userLog);
                LOG.info("User '" + data.username + "' logged in successfuly.");
                AuthToken token = new AuthToken(data.username);
                return Response.ok(g.toJson(token)).build();
            }
            else {
                return Response.status(Status.FORBIDDEN)
                        .entity("Wrong password for: " + data.username)
                        .build();
            }
        }
        else {
            return Response.status(Status.FORBIDDEN)
                    .entity("Failed login attempt for username: " + data.username)
                    .build();
        }
    }

    @GET
    @Path("/{username}")
    public Response checkUsernameAvailable(@PathParam("username") String username) {
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);
		if(user != null)
            return Response.status(Status.NOT_ACCEPTABLE)
                    .entity("User already exists with that username !")
                    .build();
        else
            return Response.status(Status.ACCEPTED)
                    .entity("That name is available !")
                    .build();
    }

    @POST
    @Path("/v2")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response doLoginV2(LoginData data,
                              @Context HttpServletRequest request,
                              @Context HttpHeaders headers) {
        LOG.fine(LOG_MESSAGE_LOGIN_ATTEMP + data.username);

        Key userKey = userKeyFactory.newKey(data.username);
        Key ctrsKey = datastore.newKeyFactory()
                .addAncestors(PathElement.of("User", data.username))
                .setKind("UserStats")
                .newKey("counters");
        // Generate automatically a key
        Key logKey = datastore.allocateId(
                datastore.newKeyFactory()
                        .addAncestors(PathElement.of("User", data.username))
                        .setKind("UserLog").newKey());

        Transaction txn = datastore.newTransaction();
        try {
            Entity user = txn.get(userKey);
            if (user == null) {
                // Username does not exist
                LOG.warning(LOG_MESSAGE_LOGIN_ATTEMP + data.username);
                return Response.status(Status.FORBIDDEN)
                        .entity(MESSAGE_INVALID_CREDENTIALS)
                        .build();
            }

            // We get the user stats from the storage
            Entity stats = txn.get(ctrsKey);
            if (stats == null) {
                stats = Entity.newBuilder(ctrsKey)
                        .set("user_stats_logins", 0L)
                        .set("user_stats_failed", 0L)
                        .set("user_first_login", Timestamp.now())
                        .set("user_last_login", Timestamp.now())
                        .build();
            }

            String hashedPWD = (String) user.getString(USER_PWD);
            if (hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
                // Login successful
                // Construct the logs
                String cityLatLong = headers.getHeaderString("X-AppEngine-CityLatLong");
                Entity log = Entity.newBuilder(logKey)
                        .set("user_login_ip", request.getRemoteAddr())
                        .set("user_login_host", request.getRemoteHost())
                        .set("user_login_latlon", cityLatLong != null
                                ? StringValue.newBuilder(cityLatLong).setExcludeFromIndexes(true).build()
                                : StringValue.newBuilder("").setExcludeFromIndexes(true).build())
                        .set("user_login_city", headers.getHeaderString("X-AppEngine-City"))
                        .set("user_login_country", headers.getHeaderString("X-AppEngine-Country"))
                        .set("user_login_time", Timestamp.now())
                        .build();

                // Get the user statistics and updates it
                // Copying information every time a user logins may not be a good solution
                // (why?)
                Entity ustats = Entity.newBuilder(ctrsKey)
                        .set("user_stats_logins", stats.getLong("user_stats_logins") + 1)
                        .set("user_stats_failed", 0L)
                        .set("user_first_login", stats.getTimestamp("user_first_login"))
                        .set("user_last_login", Timestamp.now())
                        .build();

                // Batch operation
                txn.put(log, ustats);
                txn.commit();

                // Return token
                AuthToken token = new AuthToken(data.username);
                LOG.info(LOG_MESSAGE_LOGIN_SUCCESSFUL + data.username);
                return Response.ok(g.toJson(token)).build();
            } else {
                // Incorrect password
                // Copying here is even worse. Propose a better solution!
                Entity ustats = Entity.newBuilder(ctrsKey)
                        .set("user_stats_logins", stats.getLong("user_stats_logins"))
                        .set("user_stats_failed", stats.getLong("user_stats_failed") + 1L)
                        .set("user_first_login", stats.getTimestamp("user_first_login"))
                        .set("user_last_login", stats.getTimestamp("user_last_login"))
                        .set("user_last_attempt", Timestamp.now())
                        .build();

                txn.put(ustats);
                txn.commit();
                LOG.warning(LOG_MESSAGE_WRONG_PASSWORD + data.username);
                return Response.status(Status.FORBIDDEN).entity(MESSAGE_INVALID_CREDENTIALS).build();
            }
        } catch (Exception e) {
            txn.rollback();
            LOG.severe(e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) {
                txn.rollback();
            }
        }
    }

}
