#!/usr/bin/env ruby
# frozen_string_literal: true

# urlaudit.rb — OMEGA Ruby polyglot adapter (stdlib only, no gems).
#
# Reads NDJSON lines on stdin, each {"url":"http://host/path?q=..."}, and
# for every line emits one JSON line:
#
#   {"url":..., "checks":{"open_redirect_shape":bool,
#                         "sqli_shape":bool,
#                         "ssti_shape":bool,
#                         "xss_shape":bool}}
#
# Pure string analysis of suspicious URL structures. NO network calls,
# no gems (stdlib json only). Malformed lines yield {"error": "..."}.
require 'json'
require 'uri'

checks_for = lambda do |url|
  path = url.split('?', 2)[0] || ''
  query = url.split('?', 2)[1] || ''
  # Decode percent-encoding before shape matching so payloads encoded in
  # the query string (%27 => ', %7B => {, ...) are still detected.
  begin
    path = URI.decode_www_form_component(path)
    query = URI.decode_www_form_component(query)
  rescue ArgumentError
    # leave the raw strings in place on malformed escapes
  end

  {
    # path traversal / scheme-relative redirect shapes. NOTE: check the
    # path only — '//' inside the scheme (http://) is NOT a redirect
    # shape; a scheme-relative target starts the path with '//' and
    # traversal is '../' in the path.
    'open_redirect_shape' => path.include?('../') ||
                             path.start_with?('//') ||
                             query.include?('//'),
    # SQL injection marker shapes: quote, double quote, comment, sleep()
    'sqli_shape' => (query.include?("'") || query.include?('"') ||
                     query.include?('--') ||
                     query.downcase.include?('sleep(')),
    # template injection shapes: {{...}}, {%...%}, ${...}
    'ssti_shape' => query.include?('{{') || query.include?('{%') ||
                    query.include?('${') || path.include?('{{'),
    # reflected XSS shapes: script tag, inline event handler, js: URI
    'xss_shape' => query.downcase.include?('<script') ||
                   query.downcase.include?('onerror=') ||
                   query.downcase.include?('javascript:') ||
                   path.downcase.include?('<script')
  }
end

$stdin.each_line do |line|
  line = line.strip
  next if line.empty?

  begin
    obj = JSON.parse(line)
    url = obj['url'].to_s
    if url.empty?
      puts JSON.generate('error' => 'missing url field')
    else
      puts JSON.generate('url' => url, 'checks' => checks_for.call(url))
    end
  rescue JSON::ParserError
    puts JSON.generate('error' => 'invalid json line')
  end
end
