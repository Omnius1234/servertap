package io.servertap.api.v1;

import io.javalin.http.Context;
import io.javalin.openapi.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.servertap.ServerTapMain;
import io.servertap.WebServer;
import io.servertap.api.v1.models.User;
import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.sql.*;
import java.util.ArrayList;

import static io.servertap.WebServer.authKey;

public class AuthApi {

    private final ServerTapMain main;

    private ArrayList<User> users = new ArrayList<User>();

    private Plugin userLogin;

    private Connection connection;

    public AuthApi(ServerTapMain main) {
        this.main = main;

        this.loadUsers();

        Bukkit.getScheduler().scheduleSyncDelayedTask(main, () -> {
            Plugin userLoginPlugin = Bukkit.getPluginManager().getPlugin("UserLogin");
            if (userLoginPlugin != null && userLoginPlugin.isEnabled()) {
                this.userLogin = userLoginPlugin;

                this.connection = this.dbConnect();
                this.loadUsers();
            }
        });
    }

    private Connection dbConnect() {
        Connection conn = null;
        if (this.userLogin != null) {
            String dbPath = userLogin.getConfig().getString("database.sqlite.database");
            try {
                conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
                if (conn != null) {
                    this.main.getLogger().info("Connessione al DB avvenuta");
                }
            } catch (SQLException exception) {
                this.main.getLogger().severe(exception.getMessage());
            }
        }
        return conn;
    }

    private void loadUsers() {
        try {
            if (this.connection != null) {
                String tableName = userLogin.getConfig().getString("database.sqlite.table");
                Statement stmt = this.connection.createStatement();
                ResultSet rs = stmt.executeQuery(String.format("SELECT * FROM %s", tableName));
                while (rs.next()) {
                    this.users.add(new User(rs.getString("username"), rs.getString("password")));
                }

                main.getLogger().info(this.users.toString());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean validateCredentials(String username, String password) {
        this.loadUsers();

        if (users != null) {
            for (User user : users) {
                if (user.getUsername().equals(username) && BCrypt.checkpw(password, user.getPassword())) {
                    return true;
                }
            }
        }
        return false;
    }

    @OpenApi(
            path = "/v1/login",
            methods = {HttpMethod.POST},
            summary = "Log in the user and return a JWT access token",
            tags = {"Login"},
            requestBody = @OpenApiRequestBody(
                    required = true,
                    content = {
                            @OpenApiContent(
                                    mimeType = "application/x-www-form-urlencoded",
                                    properties = {
                                            @OpenApiContentProperty(name = "username", type = "string"),
                                            @OpenApiContentProperty(name = "password", type = "string", format = "password")
                                    }
                            )
                    }
            ),
            responses = {
                    @OpenApiResponse(status = "200", content = @OpenApiContent(from = io.servertap.api.v1.models.Login.class)),
                    @OpenApiResponse(status = "401", content = @OpenApiContent(type = "application/json"))
            }
    )
    public void login(Context ctx) {
        String username = ctx.formParam("username");
        String password = ctx.formParam("password");
        if (!this.validateCredentials(username, password)) {
            ctx.status(401).json("Invalid username or password");
        } else {
            ctx.status(200).json(WebServer.generateJWT(username));
        }
    }

    @OpenApi(
            path = "/v1/refresh",
            methods = {HttpMethod.POST},
            summary = "Refresh the JWT access token",
            tags = {"Login"},
            security = @OpenApiSecurity(
                    name = "BearerAuth"
            ),
            responses = {
                    @OpenApiResponse(status = "200"),
                    @OpenApiResponse(status = "401", content = @OpenApiContent(type = "application/json"))
            }
    )
    public void refreshToken(Context ctx) {
        String token = ctx.header(WebServer.SERVERTAP_KEY_HEADER);
        Key key = new SecretKeySpec(authKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());
        Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        Claims claims = claimsJws.getBody();
        String newToken = WebServer.generateJWT(claims.getSubject());

        if(!newToken.isEmpty()) ctx.status(400).json("Invalid");
        else ctx.status(200).json(newToken);
    }
}
