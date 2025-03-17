#ifndef LIBZDB_StoppointCollection_HPP
#define LIBZDB_StoppointCollection_HPP

#include <vector>
#include <memory>
#include <libzdb/types.hpp>
#include <algorithm>

namespace zdb {
    template <class Stoppoint>
    class StoppointCollection {
      public:
        Stoppoint& push(std::unique_ptr<Stoppoint> stoppoint);
        bool contains_id(typename Stoppoint::id_type id) const;

        bool contains_address(VirtualAddr address) const;
        bool enabled_stoppoint_at_address(VirtualAddr address) const;

        Stoppoint& get_by_id(typename Stoppoint::id_type id);
        const Stoppoint& get_by_id(typename Stoppoint::id_type id) const;
        Stoppoint& get_by_address(VirtualAddr address);
        const Stoppoint& get_by_address(VirtualAddr address) const;

        void remove_by_id(typename Stoppoint::id_type id);
        void remove_by_address(VirtualAddr address);

        template <class Func>
        void for_each(Func func);
        template <class Func>
        void for_each(Func func) const;

        std::size_t size() const { return stoppoints_.size(); }
        bool empty() const { return stoppoints_.empty(); }
        
      private:
        using points_t = std::vector<std::unique_ptr<Stoppoint>>;
        points_t stoppoints_;

        typename points_t::iterator find_by_id(typename Stoppoint::id_type id);
        typename points_t::const_iterator find_by_id(typename Stoppoint::id_type id) const;
        typename points_t::iterator find_by_address(VirtualAddr address);
        typename points_t::const_iterator find_by_address(VirtualAddr address) const;
    };

    template <class Stoppoint>
    Stoppoint& StoppointCollection<Stoppoint>::push(std::unique_ptr<Stoppoint> stoppoint) {
        stoppoints_.push_back(std::move(stoppoint));
        return *stoppoints_.back();
    }   

    template <class Stoppoint>
    bool StoppointCollection<Stoppoint>::contains_id(typename Stoppoint::id_type id) const {
        return find_by_id(id) != end(stoppoints_);
    }   

    template <class Stoppoint>
    bool StoppointCollection<Stoppoint>::contains_address(VirtualAddr address) const {
        return find_by_address(address) != end(stoppoints_);
    }

    template <class Stoppoint>
    bool StoppointCollection<Stoppoint>::enabled_stoppoint_at_address(VirtualAddr address) const {
        return contains_address(address) && get_by_address(address).is_enabled();
    }

    template <class Stoppoint>
    Stoppoint& StoppointCollection<Stoppoint>::get_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        if (it == end(stoppoints_)) {
            Error::send("Stoppoint id not found: " + std::to_string(id));
        }
        return **it;
    }

    template <class Stoppoint>
    const Stoppoint& StoppointCollection<Stoppoint>::get_by_id(typename Stoppoint::id_type id) const {
        return const_cast<StoppointCollection*>(this)->get_by_id(id);
    }

    template <class Stoppoint>
    Stoppoint& StoppointCollection<Stoppoint>::get_by_address(VirtualAddr address) {
        auto it = find_by_address(address);
        if (it == end(stoppoints_)) {
            Error::send("Stoppoint address not found: " + std::to_string(address.addr()));
        }
        return **it;
    }

    template <class Stoppoint>
    const Stoppoint& StoppointCollection<Stoppoint>::get_by_address(VirtualAddr address) const {
        return const_cast<StoppointCollection*>(this)->get_by_address(address);
    }

    template <class Stoppoint>
    void StoppointCollection<Stoppoint>::remove_by_id(typename Stoppoint::id_type id) {
        auto it = find_by_id(id);
        **it.disable();
        stoppoints_.erase(it);
    }

    template <class Stoppoint>
    void StoppointCollection<Stoppoint>::remove_by_address(VirtualAddr address) {
        auto it = find_by_address(address);
        **it.disable();
        stoppoints_.erase(it);
    }
    
    template <class Stoppoint>
    template <class Func>
    void StoppointCollection<Stoppoint>::for_each(Func func) {
        std::for_each(begin(stoppoints_), end(stoppoints_), func);
    }

    template <class Stoppoint>
    template <class Func>
    void StoppointCollection<Stoppoint>::for_each(Func func) const {
        std::for_each(begin(stoppoints_), end(stoppoints_), func);
    }

    template <class Stoppoint>
    auto StoppointCollection<Stoppoint>::find_by_id(typename Stoppoint::id_type id) -> typename points_t::iterator { 
        return std::find_if(
            begin(stoppoints_), 
            end(stoppoints_),
            [=](auto& point) { return point->id() == id; }
        );
    }

    template <class Stoppoint>
    auto StoppointCollection<Stoppoint>::find_by_id(typename Stoppoint::id_type id) const -> typename points_t::const_iterator {
        return const_cast<StoppointCollection*>(this)->find_by_id(id); 
    }

    template <class Stoppoint>
    auto StoppointCollection<Stoppoint>::find_by_address(VirtualAddr address)-> typename points_t::iterator
    {
        return std::find_if(
            begin(stoppoints_), 
            end(stoppoints_),
            [=](auto& point) { return point->at_address(address); });
    }

    template <class Stoppoint>
    auto StoppointCollection<Stoppoint>::find_by_address(VirtualAddr address) const -> typename points_t::const_iterator {
        return const_cast<StoppointCollection*>(this)->find_by_address(address);
    }
} // namespace zdb
#endif // LIBZDB_StoppointCollection_HPP