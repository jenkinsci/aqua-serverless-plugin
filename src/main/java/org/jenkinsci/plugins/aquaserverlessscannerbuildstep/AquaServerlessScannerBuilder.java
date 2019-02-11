package org.jenkinsci.plugins.aquaserverlessscannerbuildstep;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.AbortException;
import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.tasks.Builder;
//import hudson.model.BuildListener;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;

import hudson.FilePath;
import hudson.model.Run;
import hudson.model.TaskListener;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;

/**
 * This is the builder class.
 * <p>
 * When a build is performed, the {@link #perform} method will be invoked.
 *
 * @author Oran Moshai
 */
public class AquaServerlessScannerBuilder extends Builder implements SimpleBuildStep{

	public static final int OK_CODE = 0;
	public static final int DISALLOWED_CODE = 4;
	private final String onDisallowed;
	private final String notCompliesCmd;
	private final String codeScanPath;
	private final String customFlags;

	private static int count;
	private static int buildId = 0;

	public synchronized static void setCount(int count) {
		AquaServerlessScannerBuilder.count = count;
	}

	public synchronized static void setBuildId(int buildId) {
		AquaServerlessScannerBuilder.buildId = buildId;
	}

	// Fields in config.jelly must match the parameter names in the
	// "DataBoundConstructor"
	@DataBoundConstructor
	public AquaServerlessScannerBuilder(
			String onDisallowed, String notCompliesCmd, String codeScanPath, String customFlags) {
		this.onDisallowed = onDisallowed;
		this.notCompliesCmd = notCompliesCmd;
		this.codeScanPath = codeScanPath;
		this.customFlags = customFlags;
	}

	/**
	 * Public access required by config.jelly to display current values in
	 * configuration screen.
	 */

	public String getOnDisallowed() {
		return onDisallowed;
	}
	public String getNotCompliesCmd() {
		return notCompliesCmd;
	}
	public String getCodeScanPath() {
		return codeScanPath;
	}
	public String getCustomFlags() {
		return customFlags;
	}

	// Returns the 'checked' state of the radio button for the step GUI
	public String isOnDisallowed(String state) {
		if (this.onDisallowed == null) {
			// default for new step GUI
			return "ignore".equals(state) ? "true" : "false";
		} else {
			return this.onDisallowed.equals(state) ? "true" : "false";
		}
	}


	@Override
	public void perform(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener)
			throws AbortException, java.lang.InterruptedException {
		// This is where you 'build' the project.
		String apiServerlessUrl = getDescriptor().getApiServerlessUrl();
		String serverlessUser = getDescriptor().getServerlessUser();
		String serverlessPassword = getDescriptor().getServerlessPassword();

		String serverlessBinaryUrl = getDescriptor().getServerlessBinaryUrl();
		String serverlessBinaryUser = getDescriptor().getServerlessBinaryUser();
		String serverlessBinaryPassword = getDescriptor().getServerlessBinaryPassword();
		if (apiServerlessUrl == null || apiServerlessUrl.trim().equals("") || serverlessUser == null || serverlessUser.trim().equals("") || serverlessPassword == null
				|| serverlessPassword.trim().equals("")) {
				throw new AbortException("Missing configuration. Please set the global configuration parameters in The \"Aqua Security\" section under  \"Manage Jenkins/Configure System\", before continuing.\n");
		}

		// Allow API urls without the protocol part, add the "https://" in this case
		if (apiServerlessUrl.indexOf("://") == -1) {
			apiServerlessUrl = "https://" + apiServerlessUrl;
		}

		// Support unique names for artifacts when there are multiple steps in the same
		// build
		String artifactSuffix, artifactName;
		if (build.hashCode() != buildId) {
			// New build
			setBuildId(build.hashCode());
			setCount(1);
			artifactSuffix = null; // When ther is only one step, there should be no suffix at all
			artifactName = "scanout.html";
		} else {
			setCount(count + 1);
			artifactSuffix = Integer.toString(count);
			artifactName = "scanout-" + artifactSuffix + ".html";
		}

		int exitCode = ScannerExecuter.execute(build, workspace, launcher, listener, artifactName, apiServerlessUrl, serverlessUser,
		serverlessPassword, notCompliesCmd, codeScanPath, customFlags, serverlessBinaryUrl, serverlessBinaryUser, serverlessBinaryPassword, onDisallowed);

		build.addAction(new AquaScannerAction(build, artifactSuffix, artifactName));

		archiveArtifacts(build, workspace, launcher, listener);

		System.out.println("exitCode: " + exitCode);
		String failedMessage = "Scanning failed.";
		switch (exitCode) {
		case OK_CODE:
				System.out.println("Scanning success.");
				break;
		case DISALLOWED_CODE:
				throw new AbortException(failedMessage);
		default:
			// This exception causes the message to appear in the Jenkins console
			throw new AbortException(failedMessage);
		}
	}

	// Archive scanout artifact
	@SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE") // No idea why this is needed
	private void archiveArtifacts(Run<?, ?> build, FilePath workspace, Launcher launcher, TaskListener listener)
			throws java.lang.InterruptedException {
		ArtifactArchiver artifactArchiver = new ArtifactArchiver("scanout*");
		artifactArchiver.perform(build, workspace, launcher, listener);
		ArtifactArchiver styleArtifactArchiver = new ArtifactArchiver("styles.css");
		styleArtifactArchiver.perform(build, workspace, launcher, listener);
	}

	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();
	}

	/**
	 * Descriptor for {@link AquaServerlessScannerBuilder}. Used as a singleton. The
	 * class is marked as public so that it can be accessed from views.
	 */
	@Symbol("aquaServerlessScanner")
	@Extension // This indicates to Jenkins that this is an implementation of an extension
				// point.
	public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
		/**
		 * To persist global configuration information, simply store it in a field and
		 * call save().
		 */
		private String apiServerlessUrl;
		private String serverlessUser;
		private String serverlessPassword;
		private String serverlessBinaryUrl;
		private String serverlessBinaryUser;
		private String serverlessBinaryPassword;

		/**
		 * In order to load the persisted global configuration, you have to call load()
		 * in the constructor.
		 */
		public DescriptorImpl() {
			load();
		}

		/**
		 * Performs on-the-fly validation of the form field 'name'.
		 *
		 * @param value
		 *            This parameter receives the value that the serverlessUser has typed.
		 * @return Indicates the outcome of the validation. This is sent to the browser.
		 */
		public FormValidation doCheckTimeout(@QueryParameter String value) throws IOException, ServletException {
			try {
				Integer.parseInt(value);
				return FormValidation.ok();
			} catch (NumberFormatException e) {
				return FormValidation.error("Must be a number");
			}
		}

		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			// Indicates that this builder can be used with all kinds of project types
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		public String getDisplayName() {
			return "Aqua Serverless Security";
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			// To persist global configuration information,
			// set that to properties and call save().
			apiServerlessUrl = formData.getString("apiServerlessUrl");
			serverlessUser = formData.getString("serverlessUser");
			serverlessPassword = formData.getString("serverlessPassword");

			serverlessBinaryUrl = formData.getString("serverlessBinaryUrl");
			serverlessBinaryUser = formData.getString("serverlessBinaryUser");
			serverlessBinaryPassword = formData.getString("serverlessBinaryPassword");
			save();
			return super.configure(req, formData);
		}

		public String getApiServerlessUrl() {
			return apiServerlessUrl;
		}
		public String getServerlessUser() {
			return serverlessUser;
		}
		public String getServerlessPassword() {
			return serverlessPassword;
		}
		public String getServerlessBinaryUrl() {
			return serverlessBinaryUrl;
		}
		public String getServerlessBinaryUser() {
			return serverlessBinaryUser;
		}
		public String getServerlessBinaryPassword() {
			return serverlessBinaryPassword;
		}
	}
}
