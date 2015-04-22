import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.projectpermissions.Projectpermissions;
import com.google.api.services.projectpermissions.model.Binding;
import com.google.api.services.projectpermissions.model.GetIamPolicyRequest;
import com.google.api.services.projectpermissions.model.Policy;
import com.google.api.services.projectpermissions.model.SetIamPolicyRequest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

/**
 * Sample IAM application that add a user by email address to a GCP project.
 * Note: The user must already be associated with 1 more GCP projects. This
 * application will not create a new user on GCP, just add them to a project.
 */
public class SampleIAMApp {

  // The GCP Project Id.
  private static String PROJECT_ID = "<add project Id>";

  // The email address of the user you want to add to the project.
  private static String EMAIL_ADDRESS_TO_ADD = "<add email>";

  // The role in which the user should be added. Possible choices are:
  // "owners", "editors", "viewers".
  private static String ROLE = "editors";

  // Client ID for native application - Create/Get these settings from the
  // Credentials section under APIs & auth in the left nav of the Cloud Console.
  private static String CLIENT_ID =
      "<add client id>";
  private static String CLIENT_SECRET = "<add client secret>";
  private static String REDIRECT_URI = "<add redirect uri>";

  // Leave this empty the first time you run. Then copy in the refresh token
  // that is provided in the output to authenticate automatically from then on.
  private static String REFRESH_TOKEN =
      "";


  public static void main(String[] args) throws Exception {
    Projectpermissions client = null;

    // Authenticate
    try {
      client = (REFRESH_TOKEN.isEmpty() ? AuthorizeClientViaWebBrowser() :
          AuthorizeClientViaRefreshToken(REFRESH_TOKEN));
    } catch (Exception e) {
      System.out.println("Error Authorizing the client.");
      e.printStackTrace();
    }

    Policy policy;
    String emailAddress = EMAIL_ADDRESS_TO_ADD;
    String memberString = "user:" + emailAddress;
    try {
      // Get current Policy.
      policy =
          client.projects().getIamPolicy(PROJECT_ID, new GetIamPolicyRequest()).execute();
      System.out.println("Current Policy for project: " + PROJECT_ID + " - " + policy);

      // Add the member to the role.
      boolean found = false;
      for (Binding binding : policy.getBindings()) {
        if (binding.getRole().equals(ROLE)) {
          if (binding.getMembers().contains((memberString))) {
            System.out.println(emailAddress + " is already in " + ROLE + " of this project.");
            break;
          } else {
            System.out.println("Attempting to add: " + emailAddress + " to " + ROLE + ".");
            binding.getMembers().add(memberString);
          }
          break;
        }
      }

      if (!found) {
        // Update the policy
        policy = client.projects()
            .setIamPolicy(PROJECT_ID,
                new SetIamPolicyRequest().setPolicy(policy)).execute();
        System.out.println("Succesfully added " + emailAddress + ".");
      }
    } catch (Exception e) {
      System.out.println("Error setting policy for: " + emailAddress);
      e.printStackTrace();
    }
  }


  private static Projectpermissions AuthorizeClientViaWebBrowser() throws Exception {
    // Set-up Authorization and Credentials.
    HttpTransport httpTransport = new NetHttpTransport();
    JsonFactory jsonFactory = new JacksonFactory();

    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
        httpTransport, jsonFactory, CLIENT_ID, CLIENT_SECRET, Arrays.asList(
            "https://www.googleapis.com/auth/cloud-platform"))
        .setAccessType("offline")
        .setApprovalPrompt("force")
        .build();

    String url = flow.newAuthorizationUrl().setRedirectUri(REDIRECT_URI).build();
    System.out.println(
        "Please open the following URL in your browser then type the authorization code:");
    System.out.println("  " + url);
    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
    String code = br.readLine();

    GoogleTokenResponse response =
        flow.newTokenRequest(code).setRedirectUri(REDIRECT_URI).execute();
    System.out.println("Set this to REFRESH_TOKEN to avoid the web browser: " +
        response.getRefreshToken());

    return AuthorizeClientViaRefreshToken(response.getRefreshToken());
  }

  private static Projectpermissions AuthorizeClientViaRefreshToken(
      String refreshToken) throws Exception {
    HttpTransport httpTransport = new NetHttpTransport();
    JsonFactory jsonFactory = new JacksonFactory();

    // Get credentials from the refresh and access tokens.
    GoogleCredential credential = new GoogleCredential.Builder()
        .setClientSecrets(CLIENT_ID, CLIENT_SECRET)
        .setJsonFactory(jsonFactory)
        .setTransport(httpTransport).build()
        .setRefreshToken(refreshToken);

    // Create a new authorized API client
    Projectpermissions client = new Projectpermissions
        .Builder(httpTransport, jsonFactory, credential)
        .setApplicationName("Driver App")
        .build();

    return client;
  }
}
