package org.jenkinsci.plugins.aquaserverlessscannerbuildstep;

import hudson.Launcher;
import hudson.EnvVars;
import hudson.Launcher.ProcStarter;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.util.ArgumentListBuilder;
import java.io.File;
import java.io.PrintStream;
import hudson.FilePath;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class does the actual execution..
 *
 * @author Oran Moshai
 */
public class ScannerExecuter {

	public static int execute(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener, String artifactName,
		  String apiServerlessUrl, String serverlessUser, String serverlessPassword,
			String notCompliesCmd, String codeScanPath, String customFlags, String serverlessBinaryUrl, 
			String serverlessBinaryUser, String serverlessBinaryPassword, String onDisallowed) {

		PrintStream print_stream = null;
		try {
			// Form input might be in $VARIABLE or ${VARIABLE} form, expand.
			// expand() is a noop for strings not in the above form.
			final EnvVars env = build.getEnvironment(listener);
			if (downloadServerlessBinary(serverlessBinaryUrl, serverlessBinaryUser, serverlessBinaryPassword, listener, workspace) != true) {
				listener.getLogger().println("Error download scanner");
			}
			ArgumentListBuilder args = new ArgumentListBuilder();

			args.add(workspace+"/scannercli", "scan", "--html", "--code-scan");
			if (!codeScanPath.trim().isEmpty()) {
				args.add(codeScanPath);
			}
			else {
				args.add(workspace);
			}
			if (!customFlags.trim().isEmpty()) {
				args.add(customFlags);
			}

			args.add("--host", apiServerlessUrl, "--user", serverlessUser, "--password");
			args.addMasked(serverlessPassword);
			
			File outFile = new File(build.getRootDir(), "out");
			Launcher.ProcStarter ps = launcher.launch();
			ps.cmds(args);
			ps.stdin(null);
			print_stream = new PrintStream(outFile, "UTF-8");
			ps.stderr(print_stream);
			ps.stdout(print_stream);
			ps.quiet(true);
			listener.getLogger().println(args.toString());
			int exitCode = ps.join(); // RUN !

			// Copy local file to workspace FilePath object (which might be on remote
			// machine)
			//FilePath workspace = build.getWorkspace();
			FilePath target = new FilePath(workspace, artifactName);
			FilePath outFilePath = new FilePath(outFile);
			outFilePath.copyTo(target);

			//css
			FilePath targetCss = new FilePath(workspace, "styles.css");
			File cssFile = new File(env.get("JENKINS_HOME") + "/plugins/aqua-security-scanner/css/", "styles.css");
			FilePath cssFilePath = new FilePath(cssFile);
			cssFilePath.copyTo(targetCss);

			String scanOutput = target.readToString();
			cleanBuildOutput(scanOutput, target, listener);
			// Possibly run a shell command on non compliance
			if (exitCode == AquaServerlessScannerBuilder.DISALLOWED_CODE && !notCompliesCmd.trim().isEmpty()) {
				ps = launcher.launch();
				args = new ArgumentListBuilder();
				args.add("bash", "-c", notCompliesCmd);
				ps.cmds(args);
				ps.stdin(null);
				ps.stderr(listener.getLogger());
				ps.stdout(listener.getLogger());
				ps.join(); // RUN !

			}
			if (onDisallowed == "ignore") {
				return 0;
			}
			return exitCode;

		} catch (RuntimeException e) {
			listener.getLogger().println("RuntimeException:" + e.toString());
			return -1;
		} catch (Exception e) {
			listener.getLogger().println("Exception:" + e.toString());
			return -1;
		} finally {
			if (print_stream != null) {
				print_stream.close();
			}
		}
	}
	//Read output save HTML and print stderr
	private static boolean cleanBuildOutput(String scanOutput, FilePath target, TaskListener listener) {

		int htmlStart = scanOutput.indexOf("<!DOCTYPE html>");
		if (htmlStart == -1)
		{
			listener.getLogger().println(scanOutput);
			return false;
		}
		listener.getLogger().println(scanOutput.substring(0,htmlStart));
		int htmlEnd = scanOutput.lastIndexOf("</html>") + 7;
		scanOutput = scanOutput.substring(htmlStart,htmlEnd);
		try
		{
			target.write(scanOutput, "UTF-8");
		}
		catch (Exception e)
		{
			listener.getLogger().println("Failed to save HTML report.");
		}

		return true;
	}

	private static boolean downloadServerlessBinary(String serverlessBinaryUrl, String serverlessBinaryUser, 
	String serverlessBinaryPassword, TaskListener listener, FilePath workspace) {

		BufferedReader httpResponseReader = null;
		try {
				// Connect to the web server endpoint
				URL serverUrl = new URL(serverlessBinaryUrl);
				HttpURLConnection urlConnection = (HttpURLConnection) serverUrl.openConnection();

				// Set HTTP method as GET
				urlConnection.setRequestMethod("GET");

				if (!serverlessBinaryUser.trim().isEmpty() && !serverlessBinaryPassword.trim().isEmpty()) {
					String usernameColonPassword = serverlessBinaryUser + ":" + serverlessBinaryPassword;
					byte[] usernameColonPasswordToByte = usernameColonPassword.getBytes("UTF-8");
					String basicAuthPayload = DatatypeConverter.printBase64Binary(usernameColonPasswordToByte);
					// Include the HTTP Basic Authentication payload
					urlConnection.addRequestProperty("Authorization", "Basic "+ basicAuthPayload);
				}

				// Read response from web server
				httpResponseReader =
								new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
				// Save scannercli binary
				InputStream scannerCliBinary = null;
				OutputStream os = null;
				try {
					scannerCliBinary = urlConnection.getInputStream();
					os = workspace.child("scannercli").write();
					final byte[] buf = new byte[8192];
					int i = 0;
					while ((i = scannerCliBinary.read(buf)) != -1) {
						os.write(buf, 0, i);
					}
				}
				catch (final Exception e) {
					listener.error("Unable to save scannercli"
							+ e.getMessage());
					return false;
				}
				finally {
					if (scannerCliBinary != null) {
						scannerCliBinary.close();
					}
					if (os != null) {
						os.close();
					}
				}
			try {
				workspace.child("scannercli").chmod(0755);
			}
			catch (final Exception e) {
				listener.error("Unable to chmod scannercli"
						+ e.getMessage());
				return false;
			}

		} catch (IOException ioe) {
				return false;
		} finally {
				if (httpResponseReader != null) {
						try {
								httpResponseReader.close();
						} catch (IOException ioe) {
								return false;
						}
				}	
			}
			
	return true;
  }

}