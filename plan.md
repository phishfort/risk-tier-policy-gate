For each open PR, analyse the code changes and classify them into 2 risk
  levels: high risk and low risk.

  High risk would include:
  - changes to authentication
  - renames or deletion of response fields in API endpoints
  - anything related to security.

  Low risk examples would be for eg:
  - changes to documentation
  - adding new fields to API endpoints

  The goal is to use this output to determine whether or not human review is
  required. Use one sub-agent to determine the risk levels of these open PRs and
  assign 'risktier:high' or 'risktier:low' labels to them. Use a sub-agent to
  Write the conditions for high vs low risk after exploring the codebase of
  @dashboard-2.0/.
