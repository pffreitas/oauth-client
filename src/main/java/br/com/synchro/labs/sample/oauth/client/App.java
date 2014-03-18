package br.com.synchro.labs.sample.oauth.client;

import java.io.IOException;
import java.util.Arrays;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * This is just SAMPLE CODE! Don't take this too seriously.
 * 
 * Guides you through the steps needed in order to get and access token.
 * 
 * @author Paulo Freitas (paulo.freitas@synchro.com.br
 */
public class App {

	/** Global instance of the HTTP transport. */
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

	/** Synchro OAuth Client ID */
	private static final String CONSUMER_KEY = "ID-65722d3434373936323333386752";
	
	/** Synchro OAuth  Client Secret. */
	private static final String CONSUMER_SECRET = "S-4d48472d343437393632333338555448";

	/** OAuth Provider root endpoint */
	private static final String OAUTH_PROVIDER = "https://homologacao2.synchro.com.br/synchro-oauth-provider/";
	
	/** Authorization code endpoint. */
	private static final String AUTHORIZATION_SERVER_URL = OAUTH_PROVIDER + "OAuth2/auth";
	
	/** Access token endpoint. */
	private static final String TOKEN_SERVER_URL = OAUTH_PROVIDER + "OAuth2/token";

	/**
	 * Executes the authorization code and access token generation.
	 *  
	 * @return A credential containing your tokens.
	 * 
	 * @throws Exception if anything goes wrong.
	 */
	private static Credential authorize() throws Exception {
		LocalServerReceiver receiver = new LocalServerReceiver.Builder()
		.setHost("0.0.0.0").setPort(8000).build();

		AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
				BearerToken.authorizationHeaderAccessMethod(), 
				HTTP_TRANSPORT,
				new JacksonFactory(), 
				new GenericUrl(TOKEN_SERVER_URL),
				new ClientParametersAuthentication(CONSUMER_KEY, CONSUMER_SECRET), 
				CONSUMER_KEY,
				AUTHORIZATION_SERVER_URL
				).setScopes(Arrays.asList("openid", "profile")).build();
		
		String redirectUri = receiver.getRedirectUri();
		AuthorizationCodeRequestUrl authUrl = flow.newAuthorizationUrl()
				.set("client_secret", CONSUMER_SECRET)
				.setState("-1")
				.set("nonce", "-1")
				.setRedirectUri(redirectUri);
		AuthorizationCodeInstalledApp.browse(authUrl.build());
		
		String code = receiver.waitForCode();
		
		TokenResponse response = flow.newTokenRequest(code).setRedirectUri(redirectUri).execute();
		return flow.createAndStoreCredential(response, "USER_ID");
	}

	/**
	 * Issues a http request to the user profile endpoint using our brand new credentials.
	 * 
	 * @param requestFactory This guy helps us with the http connection.
	 * @param credential User credentials that authorizes us.
	 * @throws IOException If the wire is pulled off.
	 */
	private static void run(HttpRequestFactory requestFactory, Credential credential )
			throws IOException {

		HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(OAUTH_PROVIDER+"OAuth2/userInfo?access_token="+credential.getAccessToken()));
		System.out.println(request.execute().parseAsString());
	}

	/**
	 * Runs the whole thing!
	 * 
	 * @param args none
	 */
	public static void main(String[] args) {
		try {
			//tries to obtain an access token.. if we can get it means that we our user really is who he claims to be, and we can let him access!
			final Credential credential = authorize();
			HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory();
			run(requestFactory, credential);
		} catch (Throwable t) {
			t.printStackTrace();
		}
		System.exit(1);
	}
}
