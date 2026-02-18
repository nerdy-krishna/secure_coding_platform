# Use the official Fluentd image as a base
FROM fluent/fluentd:v1.18-1

# --- Start of version-agnostic gem installation setup ---

# Set static ENV variables for GEM_HOME and GEM_PATH.
# Based on your previous errors, the Ruby version inside fluent/fluentd:v1.18-1 is 3.2.0.
ENV GEM_HOME=/home/fluent/.gem/ruby/3.2.0
ENV GEM_PATH=/home/fluent/.gem/ruby/3.2.0:/usr/lib/ruby/gems/3.2.0

# As root (the default user initially), create the user-specific gem directory and set permissions.
# This ensures the 'fluent' user can write to their GEM_HOME.
RUN mkdir -p ${GEM_HOME} && chown -R fluent:fluent /home/fluent/.gem

# --- Copy Fluentd configuration with correct ownership from the start ---
# Copy fluentd.conf to its destination, explicitly setting its owner to 'fluent'.
# This bypasses the need for a separate `chown` or `chmod` command after copying.
# The 'fluent' user and group exist in the fluent/fluentd base image.
COPY --chown=fluent:fluent fluentd.conf /fluentd/etc/fluent.conf

# --- Now switch to the 'fluent' user for all subsequent commands ---
USER fluent

# --- Continue with gem installation (as fluent user) ---
# Now, install the gem. It should use the GEM_HOME set above.
RUN fluent-gem install fluent-plugin-grafana-loki fluent-plugin-multi-format-parser

# --- End of version-agnostic gem installation setup ---

# --- Rest of your Dockerfile (if any other commands need to run as fluent) ---
# For example, if you have ENTRYPOINT or CMD here, they will now run as 'fluent'.