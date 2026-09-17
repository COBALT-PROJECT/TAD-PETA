# New-dataset model — taxonomy=4class, split=group

- packets: 991404
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 906652, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 2059, np.str_('stress_test'): 46224}

- split: group  (train 756674 / test 234730)
- class-weight: sqrt

==================================================================
  Hist Gradient Boosting
==================================================================
                  precision    recall  f1-score   support

          benign     0.9984    0.9945    0.9964    216534
hydra_bruteforce     0.9046    0.9655    0.9341      7960
       nmap_scan     0.9585    0.9585    0.9585       434
     stress_test     0.9611    0.9915    0.9761      9802

        accuracy                         0.9933    234730
       macro avg     0.9557    0.9775    0.9663    234730
    weighted avg     0.9936    0.9933    0.9934    234730

  overall accuracy   : 0.9933
  balanced accuracy  : 0.9775   (macro-avg recall)
  macro F1 (test)    : 0.9663
  macro F1 (train)   : 0.9962   [train-test gap = +0.0299]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  stress_tes
    benign             215340         790          13         391
    hydra_brutefor        273        7685           2           0
    nmap_scan               6          10         416           2
    stress_test            70          10           3        9719

**Best: Hist Gradient Boosting — macro-F1=0.9663, balanced-acc=0.9775, acc=0.9933**
Artifact: `models/multiclass/hgb_newdataset_4class.joblib`