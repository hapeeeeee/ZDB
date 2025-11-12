#ifndef LIBZDB_BREAKPOINT_HPP
#define LIBZDB_BREAKPOINT_HPP

#include <cstdint>
#include <libzdb/breakpoint_site.hpp>
#include <libzdb/stoppoint_collection.hpp>
#include <string>
#include <string_view>
#include <filesystem>
#include <functional>

namespace zdb {
    class Target;

    class Breakpoint {
      public:
        virtual ~Breakpoint() = default;

        Breakpoint() = delete;
        Breakpoint(const Breakpoint&) = delete;
        Breakpoint& operator=(const Breakpoint&) = delete;

        using id_type = std::int32_t;
        id_type id() const { return id_; }

        void enable();
        void disable();

        bool is_enabled() { return is_enabled_; }
        bool is_hardware() const { return is_hardware_; }
        bool is_internal() const { return is_internal_; }

        virtual void resolve() = 0;
        StoppointCollection<BreakpointSite, false>& breakpoint_sites() { return breakpoint_sites_; }
        const StoppointCollection<BreakpointSite, false>& breakpoint_sites() const { return breakpoint_sites_; }

        bool at_address(VirtualAddr addr) const {
            return breakpoint_sites_.contains_address(addr);
        }

        bool in_range(VirtualAddr low, VirtualAddr high) const {
            return !breakpoint_sites_.get_in_region(low, high).empty();
        }

        void install_hit_handler(std::function<bool(void)> on_hit) {
            on_hit_ = std::move(on_hit);
        }

        bool notify_hit() const {
            if (on_hit_) return on_hit_();
            return false;
        }

      protected:
        friend Target;
        Breakpoint(Target& tgt, bool is_internal = false, bool is_hardware = false);

      protected:
        id_type id_;
        Target* target_;
        bool is_enabled_ = false;
        bool is_hardware_ = false;
        bool is_internal_ = false;
        StoppointCollection<BreakpointSite, false> breakpoint_sites_;
        BreakpointSite::id_type next_site_id_ = 1;
        std::function<bool(void)> on_hit_;
    };

    class FunctionBreakpoint : public Breakpoint {
      public:
        void resolve() override;
        std::string_view function_name() const { return function_name_; }

      private:
        friend Target;
        FunctionBreakpoint(
            Target& tgt, 
            std::string function_name,
            bool is_internal = false,
            bool is_hardware = false 
        ): Breakpoint(tgt, is_internal, is_hardware), function_name_(std::move(function_name)) 
        {
            resolve();
        }

      private:
        std::string function_name_;
    };

    class LineBreakpoint : public Breakpoint {
      public:
        void resolve() override;
        const std::filesystem::path file() const { return file_; }
        std::size_t line() const { return line_; }

      private:
        friend Target;
        LineBreakpoint(
            Target& tgt, 
            std::filesystem::path file,
            std::size_t line,
            bool is_internal = false,
            bool is_hardware = false
        ): Breakpoint(tgt, is_internal, is_hardware), file_(std::move(file)), line_(line) 
        {
            resolve();
        }

      private:
        std::filesystem::path file_;
        std::size_t line_;
    };


    class AddressBreakpoint : public Breakpoint {
      public:
        void resolve() override;
        VirtualAddr address() const { return address_; }

      private:
        friend Target;
        AddressBreakpoint(
            Target& tgt, 
            VirtualAddr address,
            bool is_internal = false,
            bool is_hardware = false
        ): Breakpoint(tgt, is_hardware, is_internal), address_(address) {
            resolve();
        }

      private:
        VirtualAddr address_;
    };
};

#endif // LIBZDB_BREAKPOINT_HPP