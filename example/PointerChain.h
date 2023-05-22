#ifndef POINTERCHAIN_H
#define POINTERCHAIN_H

#include <tuple>
#include <stdint.h>
#include <type_traits>

// https://meghprkh.github.io/blog/posts/c++-force-inline/
// Local always inline macro.
// Makes the compiler less likely to turn what should be a compile time calculation into a runtime function call.
// (mostly applies to MSVC)
#if defined(__clang__)
#define POINTERCHAIN_FORCE_INLINE [[gnu::always_inline]] [[gnu::gnu_inline]] extern inline

#elif defined(__GNUC__)
#define POINTERCHAIN_FORCE_INLINE [[gnu::always_inline]] inline

#elif defined(_MSC_VER)
#pragma warning(error: 4714)
#define POINTERCHAIN_FORCE_INLINE __forceinline

#else
#error Unsupported compiler
#endif

/// <summary>
/// A tuple wrapper focused on convenient compile time pointer management. 
/// Represents a continous chain of pointers and offsets, so that the n-th pointer offset by the n-th offset points to the next pointer in the chain.
/// A chain with an invalid base or consisting of just a base is undefined.
/// </summary>
namespace PointerChain {
	// Implementation helpers for constructing and traversing pointer chains.
	namespace Impl {
		// Helper make functions, use PointerChain::make instead.
		template <typename PointerType, bool null_safe, std::size_t extra_offset_count = 0, typename Tb, typename... Offsets> POINTERCHAIN_FORCE_INLINE constexpr auto make(Tb&& base, Offsets&&... offsets) noexcept;
		template <typename PointerType, bool null_safe, std::size_t extra_offset_count = 0, typename Tb, typename... Offsets> POINTERCHAIN_FORCE_INLINE constexpr auto make(Tb&& base, std::tuple<Offsets...>) noexcept;

		template <typename T> struct pointer_depth {
			static constexpr std::size_t value = 0;
		};

		template <typename T> struct pointer_depth<T*> {
			static constexpr std::size_t value = 1 + pointer_depth<T>::value;
		};

		// Get the depth of a pointer, i.e. how many times it needs to be dereferenced to get to the original object.
		template <typename T> constexpr std::size_t pointer_depth_v = pointer_depth<T>::value;

		// Get the size of a parameter pack, i.e. the number of arguments passed.
		template <typename... Ts> constexpr std::size_t pack_size_v = sizeof...(Ts);

		// Check if two objects are from the same template class, regardless of template arguments.
		template <typename... Ts> struct is_same_template_class {
			static constexpr bool value = false;
		};

		// Check if two objects are from the same template class, regardless of template arguments.
		template <template <typename...> class T, typename... Ts, typename... Us> struct is_same_template_class<T<Ts...>, T<Us...>> {
			static constexpr bool value = true;
		};

		// Decay rvalue references to pass them by value.
		template <typename T> using decay_rvalue_reference_t = typename std::conditional_t<std::is_rvalue_reference_v<T>, std::decay_t<T>, T>;

		template <std::size_t, class T> using T_ = T;

		template<typename T, std::size_t... Is> POINTERCHAIN_FORCE_INLINE constexpr auto generate_tuple(std::index_sequence<Is...>) noexcept
		{
			return std::tuple<T_<Is, T>...>{};
		}

		// Create a default initialized tuple of size N with types T https://stackoverflow.com/a/37094024
		template<typename T, std::size_t N> POINTERCHAIN_FORCE_INLINE constexpr auto generate_tuple() noexcept
		{
			return generate_tuple<T>(std::make_index_sequence<N>{});
		}

		template <typename... Ts> constexpr POINTERCHAIN_FORCE_INLINE auto subtuple(Ts&&... elements)
		{
			return static_cast<std::tuple<decay_rvalue_reference_t<Ts>...>>(std::forward_as_tuple(std::forward<Ts>(elements)...));
		}

		template <std::size_t Start, std::size_t... I, typename... Ts> POINTERCHAIN_FORCE_INLINE constexpr auto subtuple(const std::tuple<Ts...>& t, std::index_sequence<I...>) noexcept
		{
			return subtuple(static_cast<std::tuple_element_t<Start + I, std::tuple<Ts...>>>(std::get<Start + I>(t))...);
		}

		// Create a subtuple from elements from indexes Start to End.
		template <std::size_t Start = 0, std::size_t End, typename... Ts> POINTERCHAIN_FORCE_INLINE constexpr auto subtuple(const std::tuple<Ts...>& t) noexcept
		{
			return subtuple<Start>(t, std::make_index_sequence<End - Start + 1>{});
		}

		// A wrapper for storing offsets of reference offsets.
		template <typename T1_ = int&, typename T2_ = int> class ref_offset_wrapper {
		public:
			ref_offset_wrapper() = delete;
			T1_ ref_offset;
			T2_ offset;

			// Will recursively add up all of the offsets in wrappers and wrapped wrappers.
			constexpr operator int() const noexcept
			{
				return static_cast<int>(ref_offset) + static_cast<int>(offset);
			}

		private:
			ref_offset_wrapper(T1_ ref_offset, T2_ offset) : ref_offset(ref_offset), offset(offset) {}
			template <typename T1, typename T2> friend POINTERCHAIN_FORCE_INLINE constexpr auto make_ref_offset_wrapper(T1& ref_offset, T2&& offset);
		};

		// Makes a ref_offset_wrapper, storing a reference offset as such and stripping references when wrapping another ref_offset_wrapper.
		template <typename T1, typename T2> POINTERCHAIN_FORCE_INLINE constexpr auto make_ref_offset_wrapper(T1& ref_offset, T2&& offset)
		{
			static_assert(std::is_integral_v<std::decay_t<T2>>, "Offset type must explicitly be an integer type.");
			if constexpr (Impl::is_same_template_class<Impl::ref_offset_wrapper<>, T1>::value) {
				return ref_offset_wrapper(static_cast<std::decay_t<decltype(ref_offset)>>(ref_offset), offset);
			}
			else {
				return ref_offset_wrapper<T1&, decay_rvalue_reference_t<T2>>(ref_offset, offset);
			}
		}

		// Unwraps the underlying type of a ref_offset_wrapper.
		template <typename T> struct unwrap_type {
			using type = typename std::decay_t<T>;
		};

		// Unwraps the underlying type of a ref_offset_wrapper.
		template <typename T> struct unwrap_type<ref_offset_wrapper<T>> {
			using type = typename unwrap_type<T>::type;
		};
	}

	// Base PointerChain class
	template <typename PointerType_, typename Tb_, bool null_safe_ = false, std::size_t extra_offset_count_ = 0, typename... Offsets_> class PtrChainBase {
		static_assert(std::conjunction_v<std::is_integral<std::decay_t<Offsets_>>...>
			|| std::disjunction_v<Impl::is_same_template_class<Impl::ref_offset_wrapper<>, std::decay_t<Offsets_>>...>,
			"Offset type must explicitly be an integer type.");

	public:
		// Use PointerChain::make instead.
		PtrChainBase() = delete;
		PtrChainBase(Tb_ base, Offsets_... offsets) : base(base), offsets(std::forward_as_tuple<Offsets_...>(std::forward<Offsets_>(offsets)...)) {}
		PtrChainBase(Tb_ base, std::tuple<Offsets_...> offsets) : base(base), offsets(offsets) {}

		virtual ~PtrChainBase() {}

		PtrChainBase(const PtrChainBase& other) : base(other.base), offsets(other.offsets) {}
		PtrChainBase(PtrChainBase&& other) : base(std::move(other.base)), offsets(std::move(other.offsets)) {}

		// Create a chain with a new pointed to type.
		template <typename TOther> POINTERCHAIN_FORCE_INLINE constexpr auto to()
		{
			return PtrChainBase<TOther, Tb_, null_safe_, extra_offset_count_, Offsets_...>(this->base, this->offsets);
		}

		// Traverse offsets up until and including N (default = all) and return a pointer from the last offset traversed.
		// At least one offset needs to be traversed or the program is ill-formed.
		template <std::size_t N = Impl::pack_size_v<Offsets_...> -extra_offset_count_ - 1> POINTERCHAIN_FORCE_INLINE constexpr auto get() noexcept
		{
			static_assert(N < Impl::pack_size_v<Offsets_...> -extra_offset_count_, "N cannot be greater than or equal to the total number of offsets");
			if constexpr (N < Impl::pack_size_v<Offsets_...> -extra_offset_count_ - 1) {
				return this->apply_(Impl::subtuple<0, extra_offset_count_ + N>(this->offsets));
			}
			else {
				return reinterpret_cast<PointerType_*>(this->apply_(this->offsets));
			}
		}

		// Create a new chain with an offset added to the last offset of the original.
		template <typename T> POINTERCHAIN_FORCE_INLINE constexpr auto operator + (T&& offset) noexcept
		{
			static_assert(std::is_integral_v<std::decay_t<T>>, "Offset type must explicitly be an integer type.");
			constexpr std::size_t offsetNum = Impl::pack_size_v<Offsets_...>;
			constexpr std::size_t lastIndex = offsetNum - 1;
			if constexpr (std::is_reference_v<std::tuple_element_t<lastIndex, std::tuple<Offsets_...>>>
				|| Impl::is_same_template_class<Impl::ref_offset_wrapper<>, std::tuple_element_t<lastIndex, std::tuple<Offsets_...>>>::value) {
				auto ref_wrapper = std::make_tuple(Impl::make_ref_offset_wrapper(std::get<lastIndex>(this->offsets), offset));
				if constexpr (offsetNum > 1) {
					auto t = std::tuple_cat(Impl::subtuple<0, lastIndex - 1>(this->offsets), ref_wrapper);
					return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, t);
				}
				else {
					return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, ref_wrapper);
				}
			}
			else {
				auto t = std::tuple_cat(Impl::subtuple<0, lastIndex - 1>(this->offsets), std::make_tuple(std::get<lastIndex>(this->offsets) + offset));
				return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, t);
			}
		}

		// Create a new chain with an offset subracted from the last offset of the original.
		template <typename T> POINTERCHAIN_FORCE_INLINE constexpr auto operator - (T&& offset) noexcept
		{
			static_assert(std::is_integral_v<std::decay_t<T>>, "Offset type must explicitly be an integer type.");
			constexpr std::size_t offsetNum = Impl::pack_size_v<Offsets_...>;
			constexpr std::size_t lastIndex = offsetNum - 1;
			if constexpr (std::is_reference_v<std::tuple_element_t<lastIndex, std::tuple<Offsets_...>>>
				|| Impl::is_same_template_class<Impl::ref_offset_wrapper<>, std::tuple_element_t<lastIndex, std::tuple<Offsets_...>>>::value) {
				auto ref_wrapper = std::make_tuple(Impl::make_ref_offset_wrapper(std::get<lastIndex>(this->offsets), -offset));
				if constexpr (offsetNum > 1) {
					auto t = std::tuple_cat(Impl::subtuple<0, lastIndex - 1>(this->offsets), ref_wrapper);
					return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, t);
				}
				else {
					return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, ref_wrapper);
				}
			}
			else {
				auto t = std::tuple_cat(Impl::subtuple<0, lastIndex - 1>(this->offsets), std::make_tuple(std::get<lastIndex>(this->offsets) - offset));
				return Impl::make<PointerType_, null_safe_, extra_offset_count_, Tb_>(this->base, t);
			}
		}

		POINTERCHAIN_FORCE_INLINE constexpr operator bool() noexcept
		{
			constexpr int64_t offsetIndex = Impl::pack_size_v<Offsets_...> -extra_offset_count_ - 2;
			if constexpr (offsetIndex >= 0) {
				void** pResult = reinterpret_cast<void**>(this->get<offsetIndex>());
				return !!*pResult;
			}
			else {
				return !!base;
			}
		}

		// Comparison operator for nullptr.
		POINTERCHAIN_FORCE_INLINE constexpr bool operator != (std::nullptr_t null) noexcept
		{
			return !!*this;
		}

		// Comparison operator for nullptr.
		POINTERCHAIN_FORCE_INLINE constexpr bool operator == (std::nullptr_t null) noexcept
		{
			return !*this;
		}

		// Dereference the pointer chain.
		POINTERCHAIN_FORCE_INLINE constexpr PointerType_& operator *() noexcept
		{
			return *this->get();
		}

		// Dereference the chain with an arrow operator.
		POINTERCHAIN_FORCE_INLINE constexpr PointerType_* operator ->() noexcept
		{
			return this->get();
		}

		// Dereference function.
		POINTERCHAIN_FORCE_INLINE constexpr PointerType_& dereference() noexcept
		{
			return *this->get();
		}

		// Dereference function with a fallback value returned when dereferencing returns nullptr.
		POINTERCHAIN_FORCE_INLINE constexpr PointerType_& dereference(PointerType_&& fallback)
		{
			return !!*this ? **this : fallback;
		}

		// Returns the current value at an offset, defaults to the last one in the chain.
		template<std::size_t I = Impl::pack_size_v<Offsets_...> +extra_offset_count_ - 1> POINTERCHAIN_FORCE_INLINE constexpr auto getOffset() const noexcept
		{
			static_assert(I < Impl::pack_size_v<Offsets_...> -extra_offset_count_, "Offset index out of bounds.");
			return std::get<I + extra_offset_count_>(offsets);
		}

		// Returns the total number of offsets in the chain.
		POINTERCHAIN_FORCE_INLINE constexpr std::size_t getNumOffsets() const noexcept
		{
			return Impl::pack_size_v<Offsets_...> -extra_offset_count_;
		}

	private:
		const Tb_ base;
		const std::tuple<Offsets_...> offsets;

		// Applies a tuple to a traversal function. If null_safe was set at instantiation, nullptr checks will be added every step of the chain.
		template <typename T = void, typename... Ts> POINTERCHAIN_FORCE_INLINE constexpr T* apply_(const std::tuple<Ts...>& t) noexcept
		{
			if constexpr (null_safe_) {
				return std::apply([this](auto &&... args) constexpr -> T* { return reinterpret_cast<T*>(this->traverse(this->base, static_cast<const unsigned int&>(args)...)); }, t);
			}
			else {
				return std::apply([this](auto &&... args) constexpr -> T* { return reinterpret_cast<T*>(this->traverse(this->base, args...)); }, t);
			}
		}

		// Chain traversal functions. If an offset is of an unsigned type, perform a nullptr check before adding it.
		template <typename Tb, typename To> POINTERCHAIN_FORCE_INLINE constexpr void* traverse(Tb base, const To& offset0) noexcept
		{
			if constexpr (std::is_same_v<typename Impl::unwrap_type<To>::type, unsigned int>) {
				if (!base) return nullptr;
			}
			return reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(base) + static_cast<int>(offset0));
		}

		template <typename Tb, typename To, typename... Args> POINTERCHAIN_FORCE_INLINE constexpr void* traverse(Tb base, const To& offset0, const Args... offsets) noexcept
		{
			if constexpr (std::is_same_v<typename Impl::unwrap_type<To>::type, unsigned int>) {
				if (!base) return nullptr;
			}
			return traverse(*reinterpret_cast<uintptr_t*>(reinterpret_cast<unsigned char*>(base) + static_cast<int>(offset0)), offsets...);
		}
	};

	template <typename PointerType, bool null_safe, std::size_t extra_offset_count, typename Tb, typename... Offsets> POINTERCHAIN_FORCE_INLINE constexpr auto Impl::make(Tb&& base, Offsets&&... offsets) noexcept
	{
		return PtrChainBase<PointerType, Impl::decay_rvalue_reference_t<decltype(base)>, null_safe, extra_offset_count, Impl::decay_rvalue_reference_t<decltype(offsets)>...>(std::forward<decltype(base)>(base), std::forward<Offsets>(offsets)...);
	}

	template <typename PointerType, bool null_safe, std::size_t extra_offset_count, typename Tb, typename... Offsets> POINTERCHAIN_FORCE_INLINE constexpr auto Impl::make(Tb&& base, std::tuple<Offsets...> offsets) noexcept
	{
		return PtrChainBase<PointerType, Impl::decay_rvalue_reference_t<decltype(base)>, null_safe, extra_offset_count, Impl::decay_rvalue_reference_t<Offsets>...>(std::forward<decltype(base)>(base), offsets);
	}

	// PointerType is the type pointed to by the chain, null_safe dictates whether EVERY offset should be treated as unsafe (unsigned).
	// The base can be of any type, references and pointers are dereferenced when traversing the pointer!
	// The offsets can either be immediate integral values or variables of types that can be implicitly converted to such.
	// Keep in mind any variable passed to PointerChain::make will be stored as a reference to that variable.
	template <typename PointerType = unsigned char, bool null_safe = false, typename Tb, typename... Offsets> POINTERCHAIN_FORCE_INLINE constexpr auto make(Tb&& base, Offsets&&... offsets) noexcept
	{
		constexpr int64_t pointerDepth = Impl::pointer_depth_v<std::decay_t<Tb>> -1;

		if constexpr (pointerDepth <= 0) {
			return Impl::make<PointerType, null_safe>(base, std::forward<Offsets>(offsets)...);
		}
		else {
			return std::apply([&](auto ... extraOffsets) constexpr -> auto { return Impl::make<PointerType, null_safe, pointerDepth>(base, static_cast<std::decay_t<decltype(extraOffsets)>>(extraOffsets)..., std::forward<Offsets>(offsets)...); }, Impl::generate_tuple<std::conditional_t<null_safe, unsigned int, int>, pointerDepth>());
		}
	}
}

#ifdef POINTERCHAIN_FORCE_INLINE
#undef POINTERCHAIN_FORCE_INLINE
#endif

#endif // !POINTERCHAIN_H