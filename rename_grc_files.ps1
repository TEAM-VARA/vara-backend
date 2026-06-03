# GRC 모듈 파일 리네임 스크립트
# GRC 핵심 기능 파일에 grc_ 접두사를 추가합니다.

$base = "C:\Users\owner\Desktop\s-prog\real\vara-backend\internal\service"

$renames = @(
    @{ Old = "finding_evaluator.go";          New = "grc_finding_evaluator.go" },
    @{ Old = "finding_defaults.go";           New = "grc_finding_defaults.go" },
    @{ Old = "ismsp_service.go";              New = "grc_ismsp_service.go" },
    @{ Old = "ismsp_rule_id.go";              New = "grc_ismsp_rule_id.go" },
    @{ Old = "ismsp_fixture.go";              New = "grc_ismsp_fixture.go" },
    @{ Old = "ismsp_fixture_normalize.go";    New = "grc_ismsp_fixture_normalize.go" },
    @{ Old = "pod_graph_evaluator.go";        New = "grc_pod_graph_evaluator.go" },
    @{ Old = "pod_graph_eval_rules.go";       New = "grc_pod_graph_eval_rules.go" },
    @{ Old = "cluster_pod_assembler.go";      New = "grc_cluster_pod_assembler.go" },
    @{ Old = "ismsp_rule_id_test.go";         New = "grc_ismsp_rule_id_test.go" },
    @{ Old = "ismsp_fixture_test.go";         New = "grc_ismsp_fixture_test.go" }
)

foreach ($r in $renames) {
    $oldPath = Join-Path $base $r.Old
    $newPath = Join-Path $base $r.New
    if (Test-Path $oldPath) {
        Rename-Item -Path $oldPath -NewName $r.New
        Write-Host "[OK] $($r.Old) -> $($r.New)"
    } else {
        Write-Host "[SKIP] $($r.Old) not found"
    }
}

Write-Host "`nDone. Run 'go build ./...' to verify."
