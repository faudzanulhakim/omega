# omega/adapters/jq/diffstat.jq — differential response diffstat for OMEGA.
#
# Input : one JSON object on stdin:
#           {"baseline": {status, headers, body},
#            "probe":    {status, headers, body}}
#         where body is a string (headers ignored by this filter).
# Output: one JSON object:
#           {"body_len_delta": <probe_len - baseline_len>,
#            "status_delta":   <true when the statuses differ>,
#            "new_tokens":     [up to 20 whitespace-separated substrings of
#                               length >= 8 that appear in the probe body but
#                               not in the baseline body]}
#
# Pure jq, no external dependencies. Only reads its stdin; never touches
# the network.

def body_len($o): (($o.body // "") | length);

. as $root |
def new_tokens:
  [ (.probe.body // "" | splits("\\s+"))
    | select(length >= 8) ]                      # unique candidate tokens
  | unique
  | map(. as $t | select(($root.baseline.body // "" | contains($t)) | not))
  | .[0:20];

{
  body_len_delta: (body_len(.probe) - body_len(.baseline)),
  status_delta: ((.probe.status // 0) != (.baseline.status // 0)),
  new_tokens: new_tokens
}
