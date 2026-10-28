"""Offline checks for the CWE-1400 and hybrid top-15 labels."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulspot.build import OUTPUT_COLUMNS
from vulspot.cwe import (
    Cwe1003Mapper,
    map_category_699_list,
    map_cwe_list,
    map_cwe_members,
    map_pillar_list,
    map_to_699,
    map_to_pillar,
    nearest_view_member,
    rollup_to_root,
    view_levels_from_xml,
)
from vulspot.config import load_config
from vulspot.cwe_labels import cwe_1400_aligned, fit_scheme, parse_cwe_ids, top15_labels

CATS = {"476": "1399", "416": "1399", "20": "1406", "122": "1399", "7": "1405"}


def _scheme():
    train = [["476"]] * 5 + [["416"]] * 4 + [["20"]] * 3 + [["7"]]
    return fit_scheme(train, CATS, k=2, min_rows=2)


def test_parse_keeps_order_and_drops_placeholders():
    assert parse_cwe_ids(["CWE-476", "NVD-CWE-Other", "CWE-416", "CWE-476"]) == ["476", "416"]
    assert parse_cwe_ids(None) == []


def test_each_cwe_gets_its_own_1400_category():
    scheme = _scheme()
    assert cwe_1400_aligned(["476", "20"], scheme.categories) == ["CWE-1399", "CWE-1406"]
    assert cwe_1400_aligned(["399", "476"], scheme.categories) == [None, "CWE-1399"]
    assert cwe_1400_aligned([], scheme.categories) == []


def test_top15_labels_each_cwe():
    scheme = _scheme()
    assert scheme.top == ("476", "416")
    assert top15_labels(["20", "416", "476"], scheme) == ["CWE-1406", "CWE-416", "CWE-476"]
    assert top15_labels(["399", "416"], scheme) == ["OTHER", "CWE-416"]


def test_small_category_and_unmapped_become_other():
    scheme = _scheme()
    assert "1405" in scheme.small
    assert "1406" not in scheme.small
    assert cwe_1400_aligned(["7"], scheme.categories) == ["CWE-1405"]
    assert top15_labels(["7"], scheme) == ["OTHER"]
    assert top15_labels(["399"], scheme) == ["OTHER"]
    assert top15_labels([], scheme) == []


def test_category_is_counted_even_beside_a_kept_cwe():
    scheme = fit_scheme(
        [["476"], ["476", "7"], ["476", "7"]],
        {"476": "1399", "7": "1405"},
        k=1,
        min_rows=2,
    )
    assert scheme.top == ("476",)
    assert "1405" not in scheme.small
    assert top15_labels(["7", "476"], scheme) == ["CWE-1405", "CWE-476"]


def test_1003_rolls_children_up_to_the_top_level():
    roots = {"CWE-119", "CWE-754"}
    view_parent = {"CWE-787": "CWE-119", "CWE-476": "CWE-754", "CWE-125": "CWE-119"}
    members = roots | set(view_parent)
    childof = {"CWE-122": ["CWE-788", "CWE-787"], "CWE-189": ["CWE-682"]}
    kw = dict(roots=roots, view_parent=view_parent, members=members, childof=childof)
    assert rollup_to_root("CWE-119", **kw) == "CWE-119"
    assert rollup_to_root("CWE-787", **kw) == "CWE-119"
    assert rollup_to_root("CWE-476", **kw) == "CWE-754"
    assert rollup_to_root("CWE-122", **kw) == "CWE-119"
    assert rollup_to_root("CWE-189", **kw) is None
    assert map_cwe_list(["CWE-125", "CWE-787", "CWE-122"], **kw) == ["CWE-119"]
    assert map_cwe_list(["CWE-476", "CWE-119"], **kw) == ["CWE-754", "CWE-119"]


def test_1003_member_list_keeps_children_and_the_nearest_outsider():
    roots = {"CWE-119", "CWE-754"}
    view_parent = {"CWE-787": "CWE-119", "CWE-476": "CWE-754", "CWE-125": "CWE-119"}
    members = roots | set(view_parent)
    childof = {"CWE-122": ["CWE-788", "CWE-787"], "CWE-189": ["CWE-682"]}
    kw = dict(members=members, childof=childof)
    assert nearest_view_member("CWE-787", **kw) == "CWE-787"
    assert nearest_view_member("CWE-119", **kw) == "CWE-119"
    assert nearest_view_member("CWE-122", **kw) == "CWE-787"
    assert nearest_view_member("CWE-189", **kw) is None
    assert map_cwe_members(["CWE-125", "CWE-787", "CWE-122"], **kw) == ["CWE-125", "CWE-787"]
    high = map_cwe_list(
        ["CWE-125", "CWE-787", "CWE-122"],
        roots=roots, view_parent=view_parent, members=members, childof=childof,
    )
    assert high == ["CWE-119"]


def test_1000_follows_the_primary_chain_to_one_pillar():
    pillars = {"CWE-664", "CWE-710"}
    primary = {
        "CWE-787": "CWE-119", "CWE-119": "CWE-118", "CWE-118": "CWE-664",
        "CWE-125": "CWE-119", "CWE-476": "CWE-710",
        "CWE-1": "CWE-2", "CWE-2": "CWE-1",
    }
    assert map_to_pillar("CWE-787", pillars=pillars, primary=primary) == "CWE-664"
    assert map_to_pillar("CWE-125", pillars=pillars, primary=primary) == "CWE-664"
    assert map_to_pillar("CWE-664", pillars=pillars, primary=primary) == "CWE-664"
    assert map_to_pillar("CWE-476", pillars=pillars, primary=primary) == "CWE-710"
    assert map_to_pillar("CWE-399", pillars=pillars, primary=primary) is None
    assert map_to_pillar("CWE-1", pillars=pillars, primary=primary) is None
    assert map_pillar_list(["CWE-787", "CWE-125", "CWE-476"], pillars=pillars, primary=primary) == [
        "CWE-664", "CWE-710",
    ]


def test_699_uses_membership_then_walks_up_the_primary_chain():
    categories = {"CWE-1218", "CWE-465", "CWE-255", "CWE-320"}
    member_of = {
        "CWE-787": ["CWE-1218"],
        "CWE-788": ["CWE-1218"],
        "CWE-825": ["CWE-465"],
        "CWE-798": ["CWE-255", "CWE-320"],
    }
    primary = {"CWE-122": "CWE-788", "CWE-416": "CWE-825", "CWE-119": "CWE-118"}
    kw = dict(categories=categories, member_of=member_of, primary=primary)
    assert map_to_699("CWE-787", **kw) == ["CWE-1218"]
    assert map_to_699("CWE-122", **kw) == ["CWE-1218"]
    assert map_to_699("CWE-416", **kw) == ["CWE-465"]
    assert map_to_699("CWE-119", **kw) == []
    assert map_to_699("CWE-1218", **kw) == ["CWE-1218"]
    assert map_to_699("CWE-798", **kw) == ["CWE-255", "CWE-320"]
    assert map_category_699_list(["CWE-798", "CWE-787", "CWE-798"], **kw) == [
        "CWE-255", "CWE-320", "CWE-1218",
    ]


def test_output_columns_are_the_current_cwe_schema():
    for name in ("cwe_1000_list", "cwe_699_list", "cwe_1003_list", "cwe_1003_high_list", "cwe_1400_list"):
        assert name in OUTPUT_COLUMNS
    assert "top15_cwe_1400" not in OUTPUT_COLUMNS


def test_cached_views_match_the_dataset_columns():
    """The on-disk CWE cache is the one stage 2 and stage 5 label with."""
    cfg = load_config(ROOT / "config.yaml")
    mapper = Cwe1003Mapper(cfg.paths.raw_nvd.parent / "cwe")
    if not mapper.available or not mapper.levels_ready():
        return
    mapper.check_views()
    got = mapper.view_lists(["CWE-122", "CWE-476"])
    assert got == {
        "cwe_1000_list": ["CWE-664", "CWE-710"],
        "cwe_699_list": ["CWE-1218", "CWE-465"],
        "cwe_1003_list": ["CWE-787", "CWE-476"],
        "cwe_1003_high_list": ["CWE-119", "CWE-754"],
    }


def test_stage5_writes_view_columns_from_cwe_list():
    import importlib.util

    import pandas as pd

    cfg = load_config(ROOT / "config.yaml")
    cwe_dir = cfg.paths.raw_nvd.parent / "cwe"
    mapper = Cwe1003Mapper(cwe_dir)
    if not mapper.available or not mapper.levels_ready():
        return
    from vulspot.cwe_labels import load_cwe1400

    spec = importlib.util.spec_from_file_location("stage5", ROOT / "05_filter_build.py")
    stage5 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage5)
    raw = ["CWE-122", "CWE-476"]
    row = {name: None for name in OUTPUT_COLUMNS}
    row["cwe_list"] = raw
    out = stage5._attach_cwe_labels(pd.DataFrame([row]), load_cwe1400(cwe_dir), mapper)
    assert list(out.columns) == OUTPUT_COLUMNS
    assert "top15_cwe_1400" not in out.columns
    for name, values in mapper.view_lists(raw).items():
        assert list(out.iloc[0][name]) == values
    assert list(out.iloc[0]["cwe_1400_list"]) == cwe_1400_aligned(parse_cwe_ids(raw), load_cwe1400(cwe_dir))


def test_view_levels_parse_members_parents_and_categories():
    xml = """
    <Weakness ID="787" Name="OOB Write"><Related_Weaknesses>
      <Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000" Ordinal="Primary"/>
    </Related_Weaknesses></Weakness>
    <Weakness ID="119" Name="Buf"><Related_Weaknesses>
      <Related_Weakness Nature="ChildOf" CWE_ID="664" View_ID="1000" Ordinal="Primary"/>
    </Related_Weaknesses></Weakness>
    <Category ID="1218" Name="Memory Buffer Errors"><Relationships>
      <Has_Member CWE_ID="787" View_ID="699"/>
    </Relationships></Category>
    <Category ID="399" Name="Resource Management Errors"></Category>
    <View ID="1000" Name="Research Concepts" Type="Graph" Status="Draft">
      <Members>
        <Has_Member CWE_ID="664" View_ID="1000"/>
        <Has_Member CWE_ID="707" View_ID="1000"/>
      </Members>
    </View>
    <View ID="699" Name="Software Development" Type="Graph" Status="Draft">
      <Members>
        <Has_Member CWE_ID="1218" View_ID="699"/>
        <Has_Member CWE_ID="399" View_ID="699"/>
      </Members>
    </View>
    """
    levels = view_levels_from_xml(xml)
    assert levels["pillars_1000"] == ["CWE-664", "CWE-707"]
    assert levels["categories_699"] == ["CWE-1218", "CWE-399"]
    assert levels["primary_1000"]["CWE-787"] == "CWE-119"
    assert levels["primary_1000"]["CWE-119"] == "CWE-664"
    assert levels["member_699"]["CWE-787"] == ["CWE-1218"]
    assert map_to_pillar("CWE-787", pillars=set(levels["pillars_1000"]), primary=levels["primary_1000"]) == "CWE-664"
    assert map_to_699(
        "CWE-787",
        categories=set(levels["categories_699"]),
        member_of=levels["member_699"],
        primary=levels["primary_1000"],
    ) == ["CWE-1218"]
