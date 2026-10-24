#pragma once
// Exact signatures from the previously attributed Explorer hook implementation.
namespace fsgwin {
inline const wchar_t* const symbolNames[8]={
#ifdef _WIN64
LR"(protected: static long __cdecl CFSFolder::_GetSize(class CFSFolder *,struct _ITEMID_CHILD const __unaligned *,struct IDFOLDER const __unaligned *,struct tagPROPVARIANT *))",
LR"(public: long __cdecl CRecursiveFolderOperation::Prepare(void))",
LR"(public: virtual long __cdecl CRecursiveFolderOperation::Do(void))",
LR"(public: virtual long __cdecl CDefCollection::Item_GetValue(struct tagITEMKEY const *,enum VALUE_ACCESS_MODE,struct _tagpropertykey const &,struct tagPROPVARIANT *,enum VALUE_STATE *))",
LR"(private: long __cdecl CDefCollection::_GetItemProperty(struct IItemStore *,struct tagITEMKEY const *,enum GIPTYPE,struct _tagpropertykey const &,int *,struct tagPROPVARIANT *))",
LR"(public: virtual long __cdecl CFSFolder::MapColumnToSCID(unsigned int,struct _tagpropertykey *))",
LR"(public: virtual long __cdecl CFSFolder::GetDetailsEx(struct _ITEMID_CHILD const __unaligned *,struct _tagpropertykey const *,struct tagVARIANT *))",
LR"(public: virtual long __cdecl CFSFolder::CompareIDs(__int64,struct _ITEMIDLIST_RELATIVE const __unaligned *,struct _ITEMIDLIST_RELATIVE const __unaligned *))"
#else
LR"(protected: static long __stdcall CFSFolder::_GetSize(class CFSFolder *,struct _ITEMID_CHILD const *,struct IDFOLDER const *,struct tagPROPVARIANT *))",
LR"(public: long __thiscall CRecursiveFolderOperation::Prepare(void))",
LR"(public: virtual long __thiscall CRecursiveFolderOperation::Do(void))",
LR"(public: virtual long __stdcall CDefCollection::Item_GetValue(struct tagITEMKEY const *,enum VALUE_ACCESS_MODE,struct _tagpropertykey const &,struct tagPROPVARIANT *,enum VALUE_STATE *))",
LR"(private: long __thiscall CDefCollection::_GetItemProperty(struct IItemStore *,struct tagITEMKEY const *,enum GIPTYPE,struct _tagpropertykey const &,int *,struct tagPROPVARIANT *))",
LR"(public: virtual long __stdcall CFSFolder::MapColumnToSCID(unsigned int,struct _tagpropertykey *))",
LR"(public: virtual long __stdcall CFSFolder::GetDetailsEx(struct _ITEMID_CHILD const *,struct _tagpropertykey const *,struct tagVARIANT *))",
LR"(public: virtual long __stdcall CFSFolder::CompareIDs(long,struct _ITEMIDLIST_RELATIVE const *,struct _ITEMIDLIST_RELATIVE const *))"
#endif
};
}
