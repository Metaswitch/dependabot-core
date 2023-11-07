# frozen_string_literal: true

require "excon"
require "dependabot/cargo/update_checker"

module Dependabot
  module Cargo
    class UpdateChecker
      class LatestVersionFinder
        CRATES_IO_DL = "https://crates.io/api/v1/crates"

        def initialize(dependency:, dependency_files:, credentials:,
                       ignored_versions:, security_advisories:)
          @dependency          = dependency
          @dependency_files    = dependency_files
          @credentials         = credentials
          @ignored_versions    = ignored_versions
          @security_advisories = security_advisories
        end

        def latest_version
          @latest_version ||= fetch_latest_version
        end

        def lowest_security_fix_version
          @lowest_security_fix_version ||= fetch_lowest_security_fix_version
        end

        private

        attr_reader :dependency, :dependency_files, :credentials,
                    :ignored_versions, :security_advisories

        def fetch_latest_version
          versions = available_versions
          versions = filter_prerelease_versions(versions)
          versions = filter_ignored_versions(versions)
          versions.max
        end

        def fetch_lowest_security_fix_version
          versions = available_versions
          versions = filter_prerelease_versions(versions)
          versions = filter_ignored_versions(versions)
          versions = filter_vulnerable_versions(versions)
          versions = filter_lower_versions(versions)
          versions.min
        end

        def filter_prerelease_versions(versions_array)
          return versions_array if wants_prerelease?

          versions_array.reject(&:prerelease?)
        end

        def filter_ignored_versions(versions_array)
          versions_array.
            reject { |v| ignore_reqs.any? { |r| r.satisfied_by?(v) } }
        end

        def filter_vulnerable_versions(versions_array)
          versions_array.
            reject { |v| security_advisories.any? { |a| a.vulnerable?(v) } }
        end

        def filter_lower_versions(versions_array)
          versions_array.
            select { |version| version > version_class.new(dependency.version) }
        end

        def available_versions
          # Sparse registries return listings in different formats.
          if is_sparse
            crates_listing.
              reject { |v| v["yanked"] }.
              map { |v| version_class.new(v.fetch("vers")) }
          else
            crates_listing.
              fetch("versions", []).
              reject { |v| v["yanked"] }.
              map { |v| version_class.new(v.fetch("num")) }
          end
        end

        def is_sparse
          return @is_sparse unless @is_sparse.nil?
          info = dependency.requirements.map { |r| r[:source] }.compact.first
          @is_sparse = info && info[:type] == "registry+sparse"
        end

        def crates_listing
          return @crates_listing unless @crates_listing.nil?
          @crates_listing = is_sparse ? crates_listing_sparse : crates_listing_non_sparse
        rescue Excon::Error::Timeout
          retrying ||= false
          raise if retrying

          retrying = true
          sleep(rand(1.0..5.0)) && retry
        end
        
        def crates_listing_non_sparse
          info = dependency.requirements.map { |r| r[:source] }.compact.first
          dl = info && info[:dl] || CRATES_IO_DL

          # Default request headers
          hdrs = { "User-Agent" => "Dependabot (dependabot.com)" }


          response = Excon.get(
            "#{dl}/#{dependency.name}",
            headers: hdrs,
            idempotent: true,
            **SharedHelpers.excon_defaults
          )

          JSON.parse(response.body)
        end

        def crates_listing_sparse
          info = dependency.requirements.map { |r| r[:source] }.compact.first
          api = info && info[:api] 
          raise "Registry uses sparse protocol but no API URI found" if api.nil?

          # Default request headers
          hdrs = { "User-Agent" => "Dependabot (dependabot.com)" }

          # crates.microsoft.com, pkgs.dev.azure.com require an auth token
          if api.include? "crates.microsoft.com"
            raise "Must specify CARGO_REGISTRIES_CRATES_MS_TOKEN" if ENV["CARGO_REGISTRIES_CRATES_MS_TOKEN"].nil?
            hdrs["Authorization"] = ENV["CARGO_REGISTRIES_CRATES_MS_TOKEN"]
          elsif api.include? "pkgs.dev.azure.com"
            raise "Must specify CARGO_REGISTRIES_AFO_TOKEN" if ENV["CARGO_REGISTRIES_AFO_TOKEN"].nil?
            hdrs["Authorization"] = ENV["CARGO_REGISTRIES_AFO_TOKEN"]
          end
          
          name = dependency.name
          prefix = case name.length
          when 1..2
            name.length
          when 3
            "3/#{name[0]}"
          else
            "#{name[0..1]}/#{name[2..3]}"
          end
        
          response = Excon.get(
            "#{api}/#{prefix}/#{dependency.name}",
            headers: hdrs,
            idempotent: true,
            **SharedHelpers.excon_defaults
          )
          
          response.body.split("\n").
            map { |v| JSON.parse(v) }
        end

        def wants_prerelease?
          if dependency.version &&
             version_class.new(dependency.version).prerelease?
            return true
          end

          dependency.requirements.any? do |req|
            reqs = (req.fetch(:requirement) || "").split(",").map(&:strip)
            reqs.any? { |r| r.match?(/[A-Za-z]/) }
          end
        end

        def ignore_reqs
          ignored_versions.map { |req| requirement_class.new(req.split(",")) }
        end

        def version_class
          Utils.version_class_for_package_manager(dependency.package_manager)
        end

        def requirement_class
          Utils.requirement_class_for_package_manager(
            dependency.package_manager
          )
        end
      end
    end
  end
end
