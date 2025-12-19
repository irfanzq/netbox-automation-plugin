# VLAN Deployment: Tagged vs Untagged Analysis

## Current Implementation

**Current State:**
- ✅ Supports: Single untagged VLAN (access mode)
- ❌ Does NOT support: Tagged VLANs
- ❌ Does NOT support: Both tagged + untagged (hybrid mode)

**Form Fields:**
- `vlan_id` (IntegerField) - Single VLAN ID (required)

**Config Generation:**
- Cumulus: `nv set interface <iface> bridge domain br_default access <vlan>`
- EOS: `switchport mode access` + `switchport access vlan <vlan>`

**NetBox Update:**
- Sets `mode = 'access'`
- Sets `untagged_vlan = <vlan_id>`
- Does NOT set `tagged_vlans`

---

## Real-World Scenarios

### Scenario 1: Access Port (Current Support ✅)
- **Use Case:** Server connection, single VLAN
- **Config:** Only untagged VLAN
- **Example:** `swp32 access 3019`
- **NetBox:** `mode='access'`, `untagged_vlan=3019`

### Scenario 2: Trunk Port (NOT Supported ❌)
- **Use Case:** Uplink to another switch, multiple VLANs
- **Config:** Only tagged VLANs
- **Example:** `swp1 vlan 3019,3020,3021`
- **NetBox:** `mode='tagged'`, `tagged_vlans=[3019,3020,3021]`

### Scenario 3: Hybrid Port (NOT Supported ❌)
- **Use Case:** Server with native VLAN + tagged VLANs
- **Config:** Both untagged + tagged VLANs
- **Example:** `swp32 access 3019` + `swp32 vlan 3000,3020`
- **NetBox:** `mode='tagged'`, `untagged_vlan=3019`, `tagged_vlans=[3000,3020]`

### Scenario 4: Your Case (swp32)
- **Device:** `access 3019` (untagged only)
- **NetBox:** `mode='tagged'`, `untagged_vlan=3019`, `tagged_vlans=[3000]`
- **Issue:** NetBox has manually added VLAN 3000 as tagged, but device doesn't have it

---

## Platform Support Analysis

### Cumulus/Mellanox (NVUE)

**Untagged VLAN:**
```bash
nv set interface <iface> bridge domain br_default access <vlan>
```

**Tagged VLANs:**
```bash
nv set interface <iface> bridge domain br_default vlan <vlan1>,<vlan2>,...
# OR for range:
nv set interface <iface> bridge domain br_default vlan <vlan1>-<vlan2>
```

**Both (Hybrid):**
```bash
nv set interface <iface> bridge domain br_default access <untagged_vlan>
nv set interface <iface> bridge domain br_default vlan <tagged_vlan1>,<tagged_vlan2>
```

**Remove Access (to convert to trunk):**
```bash
nv unset interface <iface> bridge domain br_default access
```

**Remove Tagged (to convert to access):**
```bash
nv unset interface <iface> bridge domain br_default vlan
```

### Arista EOS

**Untagged VLAN (Access Mode):**
```
interface <iface>
   switchport mode access
   switchport access vlan <vlan>
```

**Tagged VLANs (Trunk Mode):**
```
interface <iface>
   switchport mode trunk
   switchport trunk native vlan <native_vlan>  # Optional
   switchport trunk allowed vlan <vlan1>,<vlan2>,...
```

**Both (Hybrid Mode):**
```
interface <iface>
   switchport mode trunk
   switchport trunk native vlan <untagged_vlan>
   switchport trunk allowed vlan <tagged_vlan1>,<tagged_vlan2>,...
```

---

## Recommended Form Design

### Option A: Separate Fields (Recommended ✅)

```python
# Untagged VLAN (optional)
untagged_vlan = forms.IntegerField(
    required=False,
    min_value=1,
    max_value=4094,
    label="Untagged VLAN (Native VLAN)",
    help_text="Optional: Enter untagged VLAN ID (1-4094). Leave empty for trunk-only port.",
)

# Tagged VLANs (optional)
tagged_vlans = forms.CharField(
    required=False,
    label="Tagged VLANs",
    help_text="Optional: Enter tagged VLAN IDs separated by commas or ranges (e.g., '100,200-210,300'). Leave empty for access-only port.",
    widget=forms.TextInput(attrs={
        'placeholder': 'e.g., 100,200-210,300 or 3019-3099',
    }),
)
```

**Validation:**
- At least one field must be filled (untagged OR tagged OR both)
- If both are empty → Error: "Please specify at least one VLAN (untagged or tagged)"

**Advantages:**
- ✅ Clear separation of concerns
- ✅ Easy to understand
- ✅ Supports all scenarios (access, trunk, hybrid)
- ✅ Either field can be empty

### Option B: Single Field with Mode Toggle

```python
vlan_mode = forms.ChoiceField(
    choices=[
        ('access', 'Access (Untagged Only)'),
        ('trunk', 'Trunk (Tagged Only)'),
        ('hybrid', 'Hybrid (Both)'),
    ],
    label="VLAN Mode",
)

untagged_vlan = forms.IntegerField(...)  # Required if mode=access or hybrid
tagged_vlans = forms.CharField(...)       # Required if mode=trunk or hybrid
```

**Disadvantages:**
- ❌ More complex validation
- ❌ User must understand mode concepts
- ❌ Less flexible

---

## Configuration Generation Changes

### Cumulus

```python
def _generate_vlan_config(self, interface_name, untagged_vlan, tagged_vlans, platform):
    """Generate platform-specific VLAN configuration"""
    
    if platform == 'cumulus':
        commands = []
        
        # Untagged VLAN (access)
        if untagged_vlan:
            commands.append(
                f"nv set interface {interface_name} bridge domain br_default access {untagged_vlan}"
            )
        else:
            # Remove access if it exists (convert to trunk)
            commands.append(
                f"nv unset interface {interface_name} bridge domain br_default access"
            )
        
        # Tagged VLANs
        if tagged_vlans:
            # Parse VLAN list (handles ranges like "3019-3099" or "100,200,300")
            vlan_str = self._parse_vlan_list(tagged_vlans)
            commands.append(
                f"nv set interface {interface_name} bridge domain br_default vlan {vlan_str}"
            )
        else:
            # Remove tagged VLANs if they exist (convert to access)
            commands.append(
                f"nv unset interface {interface_name} bridge domain br_default vlan"
            )
        
        return "\n".join(commands)
```

### EOS

```python
def _generate_vlan_config(self, interface_name, untagged_vlan, tagged_vlans, platform):
    """Generate platform-specific VLAN configuration"""
    
    if platform == 'eos':
        commands = [f"interface {interface_name}"]
        
        if untagged_vlan and tagged_vlans:
            # Hybrid mode
            commands.append("   switchport mode trunk")
            commands.append(f"   switchport trunk native vlan {untagged_vlan}")
            vlan_str = self._parse_vlan_list(tagged_vlans)
            commands.append(f"   switchport trunk allowed vlan {vlan_str}")
        elif untagged_vlan:
            # Access mode
            commands.append("   switchport mode access")
            commands.append(f"   switchport access vlan {untagged_vlan}")
        elif tagged_vlans:
            # Trunk mode (no native VLAN)
            commands.append("   switchport mode trunk")
            vlan_str = self._parse_vlan_list(tagged_vlans)
            commands.append(f"   switchport trunk allowed vlan {vlan_str}")
        
        return "\n".join(commands)
```

---

## NetBox Update Logic

```python
def _update_netbox_interface(self, interface, untagged_vlan, tagged_vlans):
    """Update NetBox interface VLAN assignments"""
    
    # Determine mode
    if untagged_vlan and tagged_vlans:
        mode = 'tagged'  # Hybrid
    elif untagged_vlan:
        mode = 'access'  # Access only
    elif tagged_vlans:
        mode = 'tagged'  # Trunk only
    else:
        raise ValueError("At least one VLAN must be specified")
    
    # Get VLAN objects
    untagged_vlan_obj = None
    if untagged_vlan:
        untagged_vlan_obj = VLAN.objects.get(vid=untagged_vlan)
    
    tagged_vlan_objs = []
    if tagged_vlans:
        vlan_ids = self._parse_vlan_list_to_ids(tagged_vlans)
        tagged_vlan_objs = list(VLAN.objects.filter(vid__in=vlan_ids))
    
    # Update interface
    interface.mode = mode
    interface.untagged_vlan = untagged_vlan_obj
    interface.tagged_vlans.set(tagged_vlan_objs)
    interface.save()
```

---

## Recommendation: YES, Add Support ✅

### Why?

1. **Real-World Need:** Users manually add tagged VLANs in NetBox (your case)
2. **Platform Support:** Both Cumulus and EOS support hybrid mode
3. **Flexibility:** Supports all scenarios (access, trunk, hybrid)
4. **User-Friendly:** Either field can be empty (optional)

### Implementation Priority

**Phase 1 (Current):** ✅ Access mode only (untagged)
**Phase 2 (Recommended):** Add tagged VLAN support
- Form: Add `tagged_vlans` field (optional)
- Config: Generate tagged VLAN commands
- NetBox: Update `tagged_vlans` field

**Phase 3 (Future):** Hybrid mode support
- Form: Both fields can be filled
- Config: Generate both untagged + tagged commands
- NetBox: Set both `untagged_vlan` and `tagged_vlans`

---

## Form Validation Rules

```python
def clean(self):
    cleaned_data = super().clean()
    untagged_vlan = cleaned_data.get('untagged_vlan')
    tagged_vlans = cleaned_data.get('tagged_vlans')
    
    # At least one must be specified
    if not untagged_vlan and not tagged_vlans:
        raise forms.ValidationError(
            "Please specify at least one VLAN: either 'Untagged VLAN' or 'Tagged VLANs' (or both)."
        )
    
    # Parse tagged VLANs if provided
    if tagged_vlans:
        parsed_vlans = self._parse_vlan_list(tagged_vlans)
        if not parsed_vlans:
            raise forms.ValidationError(
                "Invalid tagged VLAN format. Use comma-separated list (e.g., '100,200,300') or ranges (e.g., '3019-3099')."
            )
        cleaned_data['parsed_tagged_vlans'] = parsed_vlans
    
    return cleaned_data
```

---

## Summary

**Answer: YES, add support for both tagged and untagged VLANs**

**Design:**
- ✅ Two separate fields (both optional)
- ✅ At least one must be filled
- ✅ Supports: Access (untagged only), Trunk (tagged only), Hybrid (both)
- ✅ Platform-specific config generation
- ✅ Proper NetBox mode assignment

**Benefits:**
- ✅ Handles your use case (manually added tagged VLANs)
- ✅ Supports all real-world scenarios
- ✅ Flexible and user-friendly
- ✅ Matches platform capabilities


