#!/bin/bash

# Optional aggregation for LLMS export similar to inspect_ai; noop by default
if [ "$QUARTO_PROJECT_RENDER_ALL" = "1" ]; then
    files=("index" "spec/index" "spec/format" "spec/canonicalization" "spec/verification" "spec/manifest" "spec/classifier-policy" "spec/conformance" "reference/verify" "reference/envelope" "reference/manifest" "reference/classifier" "reference/hooks")
    llms_full="_site/llms-full.txt"
    rm -f "${llms_full}"
    mv _quarto.yml _quarto.yml.bak
    for file in "${files[@]}"; do
        echo "llms: ${file}.qmd"
        quarto render "${file}.qmd" --to gfm-raw_html --quiet --no-execute
        output_file="${file}.md"
        cat "${output_file}" >> "${llms_full}"
        echo "" >> "${llms_full}"
        mv $output_file "_site/${file}.html.md"
    done
    mv _quarto.yml.bak _quarto.yml
fi


