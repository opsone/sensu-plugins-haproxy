#! /usr/bin/env ruby
# frozen_string_literal: true

require 'csv'
require 'net/http'
require 'sensu-plugin/check/cli'
require 'uri'

class CheckHaproxyStatus < Sensu::Plugin::Check::CLI
  option :hostname,
         short: '-h HOSTNAME',
         long: '--hostname HOSTNAME',
         description: 'HAproxy web stats hostname'.dup,
         required: true

  option :port,
         short: '-P PORT',
         long: '--port PORT',
         description: 'HAproxy web stats port',
         proc: proc(&:to_i),
         default: 80

  option :path,
         short: '-q STATUSPATH',
         long: '--statspath STATUSPATH',
         description: 'HAproxy web stats path',
         default: '/'

  option :username,
         short: '-u USERNAME',
         long: '--user USERNAME',
         description: 'HAproxy web stats username'

  option :password,
         short: '-p PASSWORD',
         long: '--pass PASSWORD',
         description: 'HAproxy web stats password'

  option :use_ssl,
         description: 'Use SSL to connect to HAproxy web stats',
         long: '--use-ssl',
         boolean: true,
         default: false

  option :warn_percent,
         short: '-w PERCENT',
         boolean: true,
         default: 50,
         proc: proc(&:to_i),
         description: 'Warning Percent, default: 50'

  option :crit_percent,
         short: '-c PERCENT',
         boolean: true,
         default: 25,
         proc: proc(&:to_i),
         description: 'Critical Percent, default: 25'

  option :session_warn_percent,
         short: '-W PERCENT',
         boolean: true,
         default: 75,
         proc: proc(&:to_i),
         description: 'Session Limit Warning Percent, default: 75'

  option :session_crit_percent,
         short: '-C PERCENT',
         boolean: true,
         default: 90,
         proc: proc(&:to_i),
         description: 'Session Limit Critical Percent, default: 90'

  option :backend_session_warn_percent,
         short: '-b PERCENT',
         proc: proc(&:to_i),
         description: 'Per Backend Session Limit Warning Percent'

  option :backend_session_crit_percent,
         short: '-B PERCENT',
         proc: proc(&:to_i),
         description: 'Per Backend Session Limit Critical Percent'

  option :min_warn_count,
         short: '-M COUNT',
         default: 0,
         proc: proc(&:to_i),
         description: 'Minimum Server Warn Count, default: 0'

  option :min_crit_count,
         short: '-X COUNT',
         default: 0,
         proc: proc(&:to_i),
         description: 'Minimum Server Critical Count, default: 0'

  option :service,
         short: '-s SVC',
         description: 'Service Name to Check'.dup,
         required: true

  option :exact_match,
         short: '-e',
         boolean: true,
         default: false,
         description: 'Whether service name specified with -s should be exact match or not'

  def run
    services = acquire_services

    if services.empty?
      warning "No services matching /#{config[:service]}/"
    else
      percent_up = 100 * services.count { |svc| service_up? svc } / services.size
      failed_names = services.reject { |svc| service_up? svc }.map do |svc|
        "#{svc[:pxname]}/#{svc[:svname]}#{svc[:check_status].to_s.empty? ? "" : "[#{svc[:check_status]}]"}"
      end
      critical_sessions = services.select { |svc| svc[:slim].to_i > 0 && (100 * svc[:scur].to_f / svc[:slim].to_f) > config[:session_crit_percent] } # rubocop:disable Style/NumericPredicate
      warning_sessions = services.select { |svc| svc[:slim].to_i > 0 && (100 * svc[:scur].to_f / svc[:slim].to_f) > config[:session_warn_percent] } # rubocop:disable Style/NumericPredicate

      critical_backends = services.select do |svc|
        config[:backend_session_crit_percent] &&
          svc[:svname] == 'BACKEND' &&
          svc[:slim].to_i > 0 && # rubocop:disable Style/NumericPredicate
          (100 * svc[:scur].to_f / svc[:slim].to_f) > config[:backend_session_crit_percent]
      end

      warning_backends = services.select do |svc|
        config[:backend_session_warn_percent] &&
          svc[:svname] == 'BACKEND' &&
          svc[:slim].to_i > 0 && # rubocop:disable Style/NumericPredicate
          (100 * svc[:scur].to_f / svc[:slim].to_f) > config[:backend_session_warn_percent]
      end

      status = "UP: #{percent_up}% of #{services.size} /#{config[:service]}/ services" + (failed_names.empty? ? '' : ", DOWN: #{failed_names.join(", ")}")

      if services.size < config[:min_crit_count]
        critical status
      elsif percent_up < config[:crit_percent]
        critical status
      elsif !critical_sessions.empty? && config[:backend_session_crit_percent].nil?
        critical "#{status}; Active sessions critical: #{critical_sessions.map { |s| "#{s[:scur]} of #{s[:slim]} #{s[:pxname]}.#{s[:svname]}" }.join(", ")}"
      elsif config[:backend_session_crit_percent] && !critical_backends.empty?
        critical "#{status}; Active backends critical: #{critical_backends.map { |s| "current sessions: #{s[:scur]}, maximum sessions: #{s[:smax]} for #{s[:pxname]} backend." }.join(', ')}"
      elsif services.size < config[:min_warn_count]
        warning status
      elsif percent_up < config[:warn_percent]
        warning status
      elsif !warning_sessions.empty? && config[:backend_session_warn_percent].nil?
        warning "#{status}; Active sessions warning: #{warning_sessions.map { |s| "#{s[:scur]} of #{s[:slim]} #{s[:pxname]}.#{s[:svname]}" }.join(", ")}"
      elsif config[:backend_session_warn_percent] && !warning_backends.empty?
        critical "#{status}; Active backends warning: #{warning_backends.map { |s| "current sessions: #{s[:scur]}, maximum sessions: #{s[:smax]} for #{s[:pxname]} backend." }.join(', ')}"
      else
        ok status
      end
    end
  end

  private

  def service_up?(svc)
    svc[:status].start_with?('UP') || svc[:status] == 'OPEN' || svc[:status] == 'no check' || svc[:status].start_with?('DRAIN')
  end

  def acquire_services
    res = Net::HTTP.start(config[:hostname], config[:port], use_ssl: config[:use_ssl]) do |http|
      req = Net::HTTP::Get.new("/#{config[:path]};csv;norefresh")
      req.basic_auth config[:username], config[:password] unless config[:username].nil?
      http.request(req)
    end

    unknown "Failed to fetch from #{config[:hostname]}:#{config[:port]}/#{config[:path]}: #{res.code}" unless res.code == '200'

    parsed = CSV.parse(res.body, skip_blanks: true)
    keys = parsed.shift.reject(&:nil?).map { |k| k.match(/([(\-)?\w]+)/)[0].to_sym }
    haproxy_stats = parsed.map { |line| Hash[keys.zip(line)] }

    regexp = config[:exact_match] ? Regexp.new("\A#{config[:service]}\z") : Regexp.new(config[:service].to_s)
    haproxy_stats.select do |svc|
      svc[:pxname] =~ regexp
    end.reject do |svc|
      %w[FRONTEND BACKEND].include?(svc[:svname]) || svc[:status].start_with?('MAINT')
    end
  end
end
