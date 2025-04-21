#ifndef LIBZDB_StoppointCollection_HPP
#define LIBZDB_StoppointCollection_HPP

#include <vector>
#include <memory>
#include <libzdb/types.hpp>
#include <algorithm>
#include <type_traits>
#include <libzdb/error.hpp>
#include <string>

namespace zdb {
    template <class Stoppoint, bool Owning = true>
    class StoppointCollection {
      public:
        using pointer_type = std::conditional_t<
            Owning,
            std::unique_ptr<Stoppoint>,
            Stoppoint*
        >;


        Stoppoint& push(pointer_type stoppoint);
        bool contains_id(typename Stoppoint::id_type id) const;

        bool contains_address(VirtualAddr address) const;
        bool enabled_stoppoint_at_address(VirtualAddr address) const;

        Stoppoint& get_by_id(typename Stoppoint::id_type id);
        const Stoppoint& get_by_id(typename Stoppoint::id_type id) const;
        Stoppoint& get_by_address(VirtualAddr address);
        const Stoppoint& get_by_address(VirtualAddr address) const;
        std::vector<Stoppoint*> get_in_region(VirtualAddr low, VirtualAddr high) const;

        void remove_by_id(typename Stoppoint::id_type id);
        void remove_by_address(VirtualAddr address);

        template <class Func>
        void for_each(Func func);
        template <class Func>
        void for_each(Func func) const;

        std::size_t size() const { return stoppoints_.size(); }
        bool empty() const { return stoppoints_.empty(); }
        
      private:
        using points_t = std::vector<pointer_type>;
        points_t stoppoints_;

        typename points_t::iterator find_by_id(typename Stoppoint::id_type id);
        typename points_t::const_iterator find_by_id(typename Stoppoint::id_type id) const;
        typename points_t::iterator find_by_address(VirtualAddr address);
        typename points_t::const_iterator find_by_address(VirtualAddr address) const;
    };

    template <class Stoppoint, bool Owning>
    Stoppoint& StoppointCollection<Stoppoint, Owning>::push(pointer_type stoppoint) {
        stoppoints_.push_back(std::move(stoppoint));
        return *stoppoints_.back();
    }   

    template <class Stoppoint, bool Owning>
    bool StoppointCollection<Stoppoint, Owning>::contains_id(typename Stoppoint::id_type id) const {
        return find_by_id(id) != end(stoppoints_);
    }   

    template <class Stoppoint, bool Owning>
    bool StoppointCollection<Stoppoint, Owning>::contains_address(VirtualAddr address) const {
        return find_by_address(address) != end(stoppoints_);
    }

    template <class Stoppoint, bool Owning>
    bool StoppointCollection<Stoppoint, Owning>::enabled_stoppoint_at_address(VirtualAddr address) const {
        return contains_address(address) && get_by_address(address).is_enabled();
    }

    template <class Stoppoint, bool Owning>
    Stoppoint& StoppointCollection<Stoppoint, Owning>::get_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        if (it == end(stoppoints_)) {
            Error::send("Stoppoint id not found: " + std::to_string(id));
        }
        return **it;
    }

    template <class Stoppoint, bool Owning>
    const Stoppoint& StoppointCollection<Stoppoint, Owning>::get_by_id(typename Stoppoint::id_type id) const {
        return const_cast<StoppointCollection*>(this)->get_by_id(id);
    }

    template <class Stoppoint, bool Owning>
    Stoppoint& StoppointCollection<Stoppoint, Owning>::get_by_address(VirtualAddr address) {
        auto it = find_by_address(address);
        if (it == end(stoppoints_)) {
            Error::send("Stoppoint address not found: " + std::to_string(address.addr()));
        }
        return **it;
    }

    template <class Stoppoint, bool Owning>
    const Stoppoint& StoppointCollection<Stoppoint, Owning>::get_by_address(VirtualAddr address) const {
        return const_cast<StoppointCollection*>(this)->get_by_address(address);
    }

    template <class Stoppoint, bool Owning>
    std::vector<Stoppoint*> StoppointCollection<Stoppoint, Owning>::get_in_region(VirtualAddr low, VirtualAddr high) const {
        std::vector<Stoppoint*> result;
        for (auto &stoppoint : stoppoints_) {
            if (stoppoint->in_range(low, high)) {
                result.push_back(&*stoppoint);
            }
        }
        return result;
    }

    template <class Stoppoint, bool Owning>
    void StoppointCollection<Stoppoint, Owning>::remove_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        (**it).disable();
        stoppoints_.erase(it);
    }

    template <class Stoppoint, bool Owning>
    void StoppointCollection<Stoppoint, Owning>::remove_by_address(VirtualAddr address) {
        auto it = find_by_address(address);
        (**it).disable();
        stoppoints_.erase(it);
    }
    
    template <class Stoppoint, bool Owning>
    template <class Func>
    void StoppointCollection<Stoppoint, Owning>::for_each(Func func) {
        std::for_each(begin(stoppoints_), end(stoppoints_), func);
    }

    template <class Stoppoint, bool Owning>
    template <class Func>
    void StoppointCollection<Stoppoint, Owning>::for_each(Func func) const {
        std::for_each(begin(stoppoints_), end(stoppoints_), func);
    }

    template <class Stoppoint, bool Owning>
    auto StoppointCollection<Stoppoint, Owning>::find_by_id(typename Stoppoint::id_type id) -> typename points_t::iterator { 
        return std::find_if(
            begin(stoppoints_), 
            end(stoppoints_),
            [=](auto& point) { return point->id() == id; }
        );
    }

    template <class Stoppoint, bool Owning>
    auto StoppointCollection<Stoppoint, Owning>::find_by_id(typename Stoppoint::id_type id) const -> typename points_t::const_iterator {
        return const_cast<StoppointCollection*>(this)->find_by_id(id); 
    }

    template <class Stoppoint, bool Owning>
    auto StoppointCollection<Stoppoint, Owning>::find_by_address(VirtualAddr address)-> typename points_t::iterator
    {
        return std::find_if(
            begin(stoppoints_), 
            end(stoppoints_),
            [=](auto& point) { return point->at_address(address); });
    }

    template <class Stoppoint, bool Owning>
    auto StoppointCollection<Stoppoint, Owning>::find_by_address(VirtualAddr address) const -> typename points_t::const_iterator {
        return const_cast<StoppointCollection*>(this)->find_by_address(address);
    }
} // namespace zdb
#endif // LIBZDB_StoppointCollection_HPP